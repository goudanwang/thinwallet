//! Bounded-memory prover state stores for the fixed Phase V3A experiment.

use super::secure_temp::{validate_name, SecureDirectory};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
fn release_file_cache(file: &File, offset: u64, length: u64) -> io::Result<()> {
  use std::os::fd::AsRawFd;

  const POSIX_FADV_DONTNEED: i32 = 4;
  extern "C" {
    fn posix_fadvise(fd: i32, offset: i64, length: i64, advice: i32) -> i32;
  }

  let result = unsafe {
    posix_fadvise(
      file.as_raw_fd(),
      offset as i64,
      length as i64,
      POSIX_FADV_DONTNEED,
    )
  };
  if result == 0 {
    Ok(())
  } else {
    Err(io::Error::from_raw_os_error(result))
  }
}

#[cfg(not(target_os = "linux"))]
fn release_file_cache(_file: &File, _offset: u64, _length: u64) -> io::Result<()> {
  Ok(())
}

const META_FORMAT_VERSION: u32 = 2;
const SCALAR_ENCODING: &str = "ristretto-scalar-canonical-v1";
static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

/// Construction and authentication parameters shared by state-store backends.
#[derive(Clone, Debug)]
pub struct StateStoreConfig {
  /// Data-file path for file-backed implementations.
  pub path: PathBuf,
  /// Session identifier to which the temporary state is bound.
  pub session_id: String,
  /// Key used only to authenticate temporary-file metadata.
  pub metadata_key: [u8; 32],
  /// Maximum payload bytes in one ordered chunk.
  pub chunk_size: usize,
  /// Whether metadata must survive power loss.
  pub durable: bool,
}

/// Measured I/O counters for a prover state store.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateStoreStats {
  /// Payload bytes read.
  pub bytes_read: u64,
  /// Payload bytes written.
  pub bytes_written: u64,
  /// Highest payload length reached.
  pub peak_bytes: u64,
  /// Number of complete sequential scans.
  pub full_scans: u64,
}

/// Generic ordered, bounded-memory storage for replayable prover state.
pub trait ProverStateStore {
  /// Creates an empty session-bound store.
  fn create(config: StateStoreConfig) -> io::Result<Self>
  where
    Self: Sized;
  /// Appends the next deterministic chunk.
  fn write_chunk(&mut self, chunk_index: u64, data: &[u8]) -> io::Result<()>;
  /// Reads one chunk by deterministic index.
  fn read_chunk(&mut self, chunk_index: u64) -> io::Result<Vec<u8>>;
  /// Visits all chunks in ascending index order.
  fn sequential_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()>;
  /// Truncates the payload and resets deterministic chunk ordering.
  fn truncate(&mut self) -> io::Result<()>;
  /// Removes all backing state.
  fn remove(&mut self) -> io::Result<()>;
  /// Returns current I/O counters.
  fn stats(&self) -> StateStoreStats;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StateManifest {
  format_version: u32,
  invocation_id: String,
  object_id: String,
  operator_type: String,
  element_type: String,
  logical_element_count: u64,
  byte_length: u64,
  chunk_count: u64,
  chunk_size: usize,
  encoding: String,
  checksum: [u8; 32],
  state: String,
  authentication_tag: [u8; 32],
}

fn metadata_tag(config: &StateStoreConfig, manifest: &StateManifest) -> io::Result<[u8; 32]> {
  let mut unsigned = manifest.clone();
  unsigned.authentication_tag = [0; 32];
  let mut hasher = Sha256::new();
  hasher.update(config.metadata_key);
  hasher.update(
    bincode::serialize(&unsigned)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
  );
  Ok(hasher.finalize().into())
}

fn meta_path(path: &Path) -> PathBuf {
  let mut value = path.as_os_str().to_owned();
  value.push(".meta");
  value.into()
}

#[cfg(feature = "thinwallet-experiment")]
fn artifact_category(path: &Path) -> &'static str {
  let value = path.to_string_lossy().to_ascii_lowercase();
  if value.contains("opening") || value.contains("dereference") {
    "opening_spill"
  } else {
    "sumcheck_spill"
  }
}

fn verify_manifest(
  config: &StateStoreConfig,
  directory: &SecureDirectory,
  object_name: &str,
) -> io::Result<StateManifest> {
  let manifest_name = format!("{object_name}.meta");
  let file = directory.open_file(&manifest_name, false)?;
  let mut encoded = Vec::new();
  file.take(1024 * 1024).read_to_end(&mut encoded)?;
  let manifest: StateManifest = bincode::deserialize(&encoded)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
  let expected_tag = metadata_tag(config, &manifest)?;
  if manifest.format_version != META_FORMAT_VERSION
    || manifest.invocation_id != config.session_id
    || manifest.object_id != object_name
    || manifest.element_type != "Scalar"
    || manifest.encoding != SCALAR_ENCODING
    || manifest.chunk_size != config.chunk_size
    || manifest.state != "SEALED"
    || manifest.logical_element_count.checked_mul(32) != Some(manifest.byte_length)
    || manifest.authentication_tag != expected_tag
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "state manifest binding failed",
    ));
  }
  Ok(manifest)
}

fn checksum_file(file: &File, chunk_size: usize) -> io::Result<[u8; 32]> {
  let mut file = file.try_clone()?;
  file.seek(SeekFrom::Start(0))?;
  let mut buffer = vec![0u8; chunk_size];
  let mut hasher = Sha256::new();
  loop {
    let count = file.read(&mut buffer)?;
    if count == 0 {
      break;
    }
    hasher.update(&buffer[..count]);
    buffer[..count].fill(0);
  }
  Ok(hasher.finalize().into())
}

/// Heap-backed reference implementation of [`ProverStateStore`].
pub struct InMemoryStateStore {
  config: StateStoreConfig,
  bytes: Vec<u8>,
  chunks: u64,
  stats: StateStoreStats,
}

impl ProverStateStore for InMemoryStateStore {
  fn create(config: StateStoreConfig) -> io::Result<Self> {
    if config.chunk_size == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "zero chunk size",
      ));
    }
    Ok(Self {
      config,
      bytes: Vec::new(),
      chunks: 0,
      stats: StateStoreStats::default(),
    })
  }

  fn write_chunk(&mut self, chunk_index: u64, data: &[u8]) -> io::Result<()> {
    if chunk_index != self.chunks || data.len() > self.config.chunk_size {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "non-canonical chunk order",
      ));
    }
    self.bytes.extend_from_slice(data);
    self.chunks += 1;
    self.stats.bytes_written += data.len() as u64;
    self.stats.peak_bytes = self.stats.peak_bytes.max(self.bytes.len() as u64);
    Ok(())
  }

  fn read_chunk(&mut self, chunk_index: u64) -> io::Result<Vec<u8>> {
    if chunk_index >= self.chunks {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "chunk out of range",
      ));
    }
    let start = chunk_index as usize * self.config.chunk_size;
    let end = (start + self.config.chunk_size).min(self.bytes.len());
    let value = self.bytes[start..end].to_vec();
    self.stats.bytes_read += value.len() as u64;
    Ok(value)
  }

  fn sequential_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    for index in 0..self.chunks {
      let start = index as usize * self.config.chunk_size;
      let end = (start + self.config.chunk_size).min(self.bytes.len());
      visitor(index, &self.bytes[start..end])?;
      self.stats.bytes_read += (end - start) as u64;
    }
    self.stats.full_scans += 1;
    Ok(())
  }

  fn truncate(&mut self) -> io::Result<()> {
    self.bytes.fill(0);
    self.bytes.clear();
    self.chunks = 0;
    Ok(())
  }

  fn remove(&mut self) -> io::Result<()> {
    self.truncate()
  }

  fn stats(&self) -> StateStoreStats {
    self.stats
  }
}

/// Ordered temporary-file implementation with authenticated metadata.
pub struct FileBackedStateStore {
  config: StateStoreConfig,
  directory: SecureDirectory,
  file: File,
  temporary_name: String,
  object_name: String,
  length: u64,
  chunks: u64,
  sealed_checksum: Option<[u8; 32]>,
  stats: StateStoreStats,
  removed: bool,
}

impl FileBackedStateStore {
  fn manifest(&self, checksum: [u8; 32]) -> io::Result<StateManifest> {
    let operator_type = if self.object_name.contains("comb-ops") {
      "comb_ops"
    } else if self.object_name.contains("comb-mem") {
      "comb_mem"
    } else {
      "v3a_scalar_state"
    };
    let mut manifest = StateManifest {
      format_version: META_FORMAT_VERSION,
      invocation_id: self.config.session_id.clone(),
      object_id: self.object_name.clone(),
      operator_type: operator_type.to_owned(),
      element_type: "Scalar".to_owned(),
      logical_element_count: self.length / 32,
      byte_length: self.length,
      chunk_count: self.chunks,
      chunk_size: self.config.chunk_size,
      encoding: SCALAR_ENCODING.to_owned(),
      checksum,
      state: "SEALED".to_owned(),
      authentication_tag: [0; 32],
    };
    manifest.authentication_tag = metadata_tag(&self.config, &manifest)?;
    Ok(manifest)
  }

  pub(crate) fn release_cache(&mut self) -> io::Result<()> {
    if self.sealed_checksum.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "V3A object already sealed",
      ));
    }
    self.file.sync_data()?;
    let checksum = checksum_file(&self.file, self.config.chunk_size)?;
    let manifest = self.manifest(checksum)?;
    let encoded = bincode::serialize(&manifest)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary_manifest = format!("{}.meta.{nonce}.tmp", self.object_name);
    let mut manifest_file = self.directory.create_file_exclusive(&temporary_manifest)?;
    manifest_file.write_all(&encoded)?;
    manifest_file.sync_data()?;
    self
      .directory
      .rename(&self.temporary_name, &self.object_name)?;
    self
      .directory
      .rename(&temporary_manifest, &format!("{}.meta", self.object_name))?;
    self.directory.sync()?;
    self.sealed_checksum = Some(checksum);
    release_file_cache(&self.file, 0, self.length)
  }

  fn verify_payload(&self) -> io::Result<StateManifest> {
    let manifest = verify_manifest(&self.config, &self.directory, &self.object_name)?;
    let file = self.directory.open_file(&self.object_name, false)?;
    if file.metadata()?.len() != manifest.byte_length
      || checksum_file(&file, self.config.chunk_size)? != manifest.checksum
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "V3A payload completion check failed",
      ));
    }
    Ok(manifest)
  }
}

impl ProverStateStore for FileBackedStateStore {
  fn create(config: StateStoreConfig) -> io::Result<Self> {
    let mut config = config;
    if config.chunk_size == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "zero chunk size",
      ));
    }
    if config.path.is_relative() {
      config.path = std::env::current_dir()?.join(&config.path);
    }
    let parent = config
      .path
      .parent()
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing V3A parent"))?;
    let directory = SecureDirectory::prepare(parent)?;
    let object_name = config
      .path
      .file_name()
      .and_then(|value| value.to_str())
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid V3A object name"))?
      .to_owned();
    validate_name(&object_name)?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!("{object_name}.{nonce}.tmp");
    if directory.entry_exists(&object_name)?
      || directory.entry_exists(&format!("{object_name}.meta"))?
    {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "V3A spill target already exists",
      ));
    }
    let file = directory.create_file_exclusive(&temporary_name)?;
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::register_temp_artifact(
        &directory.path().join(&temporary_name),
        artifact_category(&config.path),
      );
    }
    let store = Self {
      config,
      directory,
      file,
      temporary_name,
      object_name,
      length: 0,
      chunks: 0,
      sealed_checksum: None,
      stats: StateStoreStats::default(),
      removed: false,
    };
    Ok(store)
  }

  fn write_chunk(&mut self, chunk_index: u64, data: &[u8]) -> io::Result<()> {
    if self.sealed_checksum.is_some()
      || chunk_index != self.chunks
      || data.is_empty()
      || data.len() > self.config.chunk_size
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "non-canonical chunk order",
      ));
    }
    self.file.seek(SeekFrom::End(0))?;
    self.file.write_all(data)?;
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_artifact_write(&self.config.path, data.len() as u64);
    self.length += data.len() as u64;
    self.chunks += 1;
    self.stats.bytes_written += data.len() as u64;
    self.stats.peak_bytes = self.stats.peak_bytes.max(self.length);
    Ok(())
  }

  fn read_chunk(&mut self, chunk_index: u64) -> io::Result<Vec<u8>> {
    if chunk_index >= self.chunks {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "chunk out of range",
      ));
    }
    self.verify_payload()?;
    let start = chunk_index * self.config.chunk_size as u64;
    let remaining = self.length.saturating_sub(start) as usize;
    let length = remaining.min(self.config.chunk_size);
    let mut bytes = vec![0u8; length];
    self.file.seek(SeekFrom::Start(start))?;
    self.file.read_exact(&mut bytes)?;
    self.stats.bytes_read += length as u64;
    release_file_cache(&self.file, start, length as u64)?;
    Ok(bytes)
  }

  fn sequential_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    let manifest = self.verify_payload()?;
    self.file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; self.config.chunk_size];
    for index in 0..manifest.chunk_count {
      let remaining = manifest.byte_length - index * self.config.chunk_size as u64;
      let length = (remaining as usize).min(buffer.len());
      self.file.read_exact(&mut buffer[..length])?;
      visitor(index, &buffer[..length])?;
      self.stats.bytes_read += length as u64;
      buffer[..length].fill(0);
    }
    self.stats.full_scans += 1;
    release_file_cache(&self.file, 0, self.length)?;
    Ok(())
  }

  fn truncate(&mut self) -> io::Result<()> {
    if self.sealed_checksum.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "cannot truncate sealed V3A object",
      ));
    }
    self.file.set_len(0)?;
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_artifact_truncate(&self.config.path);
    self.length = 0;
    self.chunks = 0;
    Ok(())
  }

  fn remove(&mut self) -> io::Result<()> {
    if self.removed {
      return Ok(());
    }
    let _ = self.file.set_len(0);
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::record_artifact_truncate(&self.config.path);
      thinwallet_instrumentation::record_artifact_remove(&self.config.path);
      thinwallet_instrumentation::record_artifact_remove(&meta_path(&self.config.path));
    }
    let temporary_result = self.directory.remove_file(&self.temporary_name);
    let data_result = self.directory.remove_file(&self.object_name);
    let meta_result = self
      .directory
      .remove_file(&format!("{}.meta", self.object_name));
    let sync_result = self.directory.sync();
    self.removed = true;
    temporary_result
      .and(data_result)
      .and(meta_result)
      .and(sync_result)
  }

  fn stats(&self) -> StateStoreStats {
    self.stats
  }
}

impl Drop for FileBackedStateStore {
  fn drop(&mut self) {
    let _ = self.remove();
  }
}

/// Read-only mmap implementation used to audit mapped versus resident memory.
pub struct MmapReadOnlyStateStore {
  config: StateStoreConfig,
  map: Mmap,
  chunks: u64,
  stats: StateStoreStats,
}

impl ProverStateStore for MmapReadOnlyStateStore {
  fn create(config: StateStoreConfig) -> io::Result<Self> {
    let mut config = config;
    if config.path.is_relative() {
      config.path = std::env::current_dir()?.join(&config.path);
    }
    let parent = config
      .path
      .parent()
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing V3A parent"))?;
    let directory = SecureDirectory::open(parent)?;
    let object_name = config
      .path
      .file_name()
      .and_then(|value| value.to_str())
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid V3A object name"))?;
    let manifest = verify_manifest(&config, &directory, object_name)?;
    let file = directory.open_file(object_name, false)?;
    if checksum_file(&file, config.chunk_size)? != manifest.checksum {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "mapped V3A payload checksum mismatch",
      ));
    }
    // Mapping is read-only; callers must still account mapped bytes separately from RSS.
    let map = unsafe { MmapOptions::new().map(&file)? };
    if map.len() as u64 != manifest.byte_length {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "state length mismatch",
      ));
    }
    Ok(Self {
      config,
      map,
      chunks: manifest.chunk_count,
      stats: StateStoreStats::default(),
    })
  }

  fn write_chunk(&mut self, _chunk_index: u64, _data: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
      io::ErrorKind::Unsupported,
      "read-only state store",
    ))
  }

  fn read_chunk(&mut self, chunk_index: u64) -> io::Result<Vec<u8>> {
    if chunk_index >= self.chunks {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "chunk out of range",
      ));
    }
    let start = chunk_index as usize * self.config.chunk_size;
    let end = (start + self.config.chunk_size).min(self.map.len());
    let value = self.map[start..end].to_vec();
    self.stats.bytes_read += value.len() as u64;
    Ok(value)
  }

  fn sequential_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    for index in 0..self.chunks {
      let start = index as usize * self.config.chunk_size;
      let end = (start + self.config.chunk_size).min(self.map.len());
      visitor(index, &self.map[start..end])?;
      self.stats.bytes_read += (end - start) as u64;
    }
    self.stats.full_scans += 1;
    Ok(())
  }

  fn truncate(&mut self) -> io::Result<()> {
    Err(io::Error::new(
      io::ErrorKind::Unsupported,
      "read-only state store",
    ))
  }

  fn remove(&mut self) -> io::Result<()> {
    Err(io::Error::new(
      io::ErrorKind::Unsupported,
      "read-only state store",
    ))
  }

  fn stats(&self) -> StateStoreStats {
    self.stats
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;

  fn config(name: &str) -> StateStoreConfig {
    let root = std::env::temp_dir().join(format!("thinwallet-v3a-tests-{}", std::process::id()));
    StateStoreConfig {
      path: root.join(format!("v3a-{name}")),
      session_id: name.to_owned(),
      metadata_key: [0x42; 32],
      chunk_size: 32,
      durable: true,
    }
  }

  #[test]
  fn in_memory_preserves_order() {
    let mut store = InMemoryStateStore::create(config("memory")).unwrap();
    store.write_chunk(0, &[1; 32]).unwrap();
    store.write_chunk(1, &[2; 32]).unwrap();
    assert_eq!(store.read_chunk(1).unwrap(), vec![2; 32]);
  }

  #[test]
  fn file_metadata_detects_tampering_and_cleans_up() {
    let config = config("file");
    let path = config.path.clone();
    let metadata = meta_path(&path);
    {
      let mut store = FileBackedStateStore::create(config.clone()).unwrap();
      store.write_chunk(0, &[3; 32]).unwrap();
      store.release_cache().unwrap();
      assert_eq!(store.read_chunk(0).unwrap(), vec![3; 32]);
      let mut bytes = fs::read(&metadata).unwrap();
      let middle = bytes.len() / 2;
      bytes[middle] ^= 1;
      fs::write(&metadata, bytes).unwrap();
      assert!(store.read_chunk(0).is_err());
    }
    assert!(!path.exists());
    assert!(!metadata.exists());
  }

  #[test]
  fn file_store_rejects_truncated_and_checksum_mismatched_payloads() {
    let config = config("payload-integrity");
    let path = config.path.clone();
    let mut store = FileBackedStateStore::create(config).unwrap();
    store.write_chunk(0, &[6; 32]).unwrap();
    store.release_cache().unwrap();

    std::fs::OpenOptions::new()
      .write(true)
      .open(&path)
      .unwrap()
      .set_len(16)
      .unwrap();
    assert!(store.read_chunk(0).is_err());

    fs::write(&path, [7; 32]).unwrap();
    assert!(store.read_chunk(0).is_err());
  }

  #[test]
  fn graceful_cancellation_removes_creating_and_sealed_state() {
    let creating = config("cancel-creating");
    let creating_path = creating.path.clone();
    {
      let mut store = FileBackedStateStore::create(creating).unwrap();
      store.write_chunk(0, &[8; 32]).unwrap();
    }
    assert!(!creating_path.exists());
    assert!(!meta_path(&creating_path).exists());

    let sealed = config("cancel-sealed");
    let sealed_path = sealed.path.clone();
    {
      let mut store = FileBackedStateStore::create(sealed).unwrap();
      store.write_chunk(0, &[9; 32]).unwrap();
      store.release_cache().unwrap();
    }
    assert!(!sealed_path.exists());
    assert!(!meta_path(&sealed_path).exists());
  }

  #[test]
  fn mmap_store_reads_authenticated_chunks_without_writing() {
    let config = config("mmap");
    let path = config.path.clone();
    let metadata = meta_path(&path);
    {
      let mut writer = FileBackedStateStore::create(config.clone()).unwrap();
      writer.write_chunk(0, &[4; 32]).unwrap();
      writer.write_chunk(1, &[5; 32]).unwrap();
      writer.release_cache().unwrap();
      let mut store = MmapReadOnlyStateStore::create(config).unwrap();
      assert_eq!(store.read_chunk(0).unwrap(), vec![4; 32]);
      assert_eq!(store.read_chunk(1).unwrap(), vec![5; 32]);
      let mut chunks = Vec::new();
      store
        .sequential_scan(&mut |index, bytes| {
          chunks.push((index, bytes.to_vec()));
          Ok(())
        })
        .unwrap();
      assert_eq!(chunks, vec![(0, vec![4; 32]), (1, vec![5; 32])]);
      assert!(store.write_chunk(2, b"x").is_err());
      assert!(store.truncate().is_err());
    }

    assert!(!path.exists());
    assert!(!metadata.exists());
  }
}
