//! Session-bound multi-object prover storage for Phase V3B.
#![allow(missing_docs)]

use super::secure_temp::{validate_name, SecureDirectory};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(feature = "thinwallet-experiment")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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

const ENCODING_VERSION: &str = "ristretto-scalar-canonical-v1";
const FILE_FORMAT_VERSION: u32 = 2;
static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct StateObjectDescriptor {
  pub object_id: String,
  pub proof_session: String,
  pub backend_revision: String,
  pub operator_id: String,
  pub element_type: String,
  pub logical_element_count: u64,
  pub chunk_size: usize,
  pub canonical_encoding_version: String,
}

impl StateObjectDescriptor {
  pub fn canonical(
    object_id: impl Into<String>,
    proof_session: impl Into<String>,
    backend_revision: impl Into<String>,
    operator_id: impl Into<String>,
    element_type: impl Into<String>,
    logical_element_count: u64,
    chunk_size: usize,
  ) -> Self {
    Self {
      object_id: object_id.into(),
      proof_session: proof_session.into(),
      backend_revision: backend_revision.into(),
      operator_id: operator_id.into(),
      element_type: element_type.into(),
      logical_element_count,
      chunk_size,
      canonical_encoding_version: ENCODING_VERSION.to_owned(),
    }
  }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct MultiObjectStoreStats {
  pub bytes_read: u64,
  pub bytes_written: u64,
  pub full_scans: u64,
  pub replay_scans: u64,
  pub range_reads: u64,
  pub temporary_storage_peak_bytes: u64,
  pub read_time_ns: u64,
  pub write_time_ns: u64,
  pub fsync_time_ns: u64,
  pub fsync_calls: u64,
  pub skipped_fsync_calls: u64,
  pub cleanup_time_ns: u64,
  pub objects_created: u64,
  pub objects_deleted: u64,
  pub append_calls: u64,
  pub seal_calls: u64,
  pub seek_calls: u64,
  pub data_write_calls: u64,
  pub metadata_write_calls: u64,
  pub sync_data_calls: u64,
  pub largest_read_bytes: u64,
  pub largest_write_bytes: u64,
  pub range_read_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDurability {
  SecurityCriticalDurable,
  EphemeralCorrectnessOnly,
}

#[derive(Clone, Debug)]
pub struct MultiObjectStoreConfig {
  pub root: PathBuf,
  pub proof_session: String,
  pub backend_revision: String,
  pub metadata_key: [u8; 32],
  pub maximum_chunk_bytes: usize,
  pub maximum_temporary_storage_bytes: u64,
  pub durability: StateDurability,
}

pub trait ProverStateStore {
  fn create_object(&mut self, descriptor: StateObjectDescriptor) -> io::Result<()>;
  fn append_chunk(&mut self, object_id: &str, chunk_index: u64, data: &[u8]) -> io::Result<()>;
  fn seal_object(&mut self, object_id: &str) -> io::Result<[u8; 32]>;
  fn sequential_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()>;
  fn range_read(&mut self, object_id: &str, offset: u64, length: usize) -> io::Result<Vec<u8>>;
  fn replay_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()>;
  fn delete_object(&mut self, object_id: &str) -> io::Result<()>;
  fn abort_session_cleanup(&mut self) -> io::Result<()>;
  fn stats(&self) -> MultiObjectStoreStats;
}

#[derive(Clone, Debug)]
struct MemoryObject {
  descriptor: StateObjectDescriptor,
  chunks: Vec<Vec<u8>>,
  sealed_checksum: Option<[u8; 32]>,
}

pub struct MultiObjectInMemoryStateStore {
  config: MultiObjectStoreConfig,
  objects: HashMap<String, MemoryObject>,
  stats: MultiObjectStoreStats,
  current_bytes: u64,
}

impl MultiObjectInMemoryStateStore {
  pub fn create(config: MultiObjectStoreConfig) -> io::Result<Self> {
    validate_config(&config)?;
    Ok(Self {
      config,
      objects: HashMap::new(),
      stats: MultiObjectStoreStats::default(),
      current_bytes: 0,
    })
  }
}

impl ProverStateStore for MultiObjectInMemoryStateStore {
  fn create_object(&mut self, descriptor: StateObjectDescriptor) -> io::Result<()> {
    validate_descriptor(&self.config, &descriptor)?;
    if self.objects.contains_key(&descriptor.object_id) {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "duplicate object",
      ));
    }
    self.objects.insert(
      descriptor.object_id.clone(),
      MemoryObject {
        descriptor,
        chunks: Vec::new(),
        sealed_checksum: None,
      },
    );
    Ok(())
  }

  fn append_chunk(&mut self, object_id: &str, chunk_index: u64, data: &[u8]) -> io::Result<()> {
    let object = self
      .objects
      .get_mut(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    validate_append(
      &self.config,
      &object.descriptor,
      object.chunks.len() as u64,
      chunk_index,
      data,
    )?;
    if object.sealed_checksum.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "sealed object",
      ));
    }
    let next = self.current_bytes + data.len() as u64;
    if next > self.config.maximum_temporary_storage_bytes {
      return Err(io::Error::new(
        io::ErrorKind::OutOfMemory,
        "temporary storage budget exceeded",
      ));
    }
    object.chunks.push(data.to_vec());
    self.current_bytes = next;
    self.stats.bytes_written += data.len() as u64;
    self.stats.temporary_storage_peak_bytes = self.stats.temporary_storage_peak_bytes.max(next);
    Ok(())
  }

  fn seal_object(&mut self, object_id: &str) -> io::Result<[u8; 32]> {
    let object = self
      .objects
      .get_mut(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    let checksum = checksum_chunks(&object.chunks);
    object.sealed_checksum = Some(checksum);
    Ok(checksum)
  }

  fn sequential_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    let object = self
      .objects
      .get(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    let expected = object
      .sealed_checksum
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsealed object"))?;
    if checksum_chunks(&object.chunks) != expected {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object checksum mismatch",
      ));
    }
    for (index, chunk) in object.chunks.iter().enumerate() {
      visitor(index as u64, chunk)?;
      self.stats.bytes_read += chunk.len() as u64;
    }
    self.stats.full_scans += 1;
    Ok(())
  }

  fn range_read(&mut self, object_id: &str, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    let object = self
      .objects
      .get(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    let bytes = object.chunks.concat();
    let start = offset as usize;
    let end = start
      .checked_add(length)
      .filter(|end| *end <= bytes.len())
      .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range outside object"))?;
    let result = bytes[start..end].to_vec();
    self.stats.bytes_read += result.len() as u64;
    self.stats.range_reads += 1;
    Ok(result)
  }

  fn replay_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    self.sequential_scan(object_id, visitor)?;
    self.stats.replay_scans += 1;
    Ok(())
  }

  fn delete_object(&mut self, object_id: &str) -> io::Result<()> {
    if let Some(mut object) = self.objects.remove(object_id) {
      for chunk in &mut object.chunks {
        chunk.fill(0);
        self.current_bytes -= chunk.len() as u64;
      }
    }
    Ok(())
  }

  fn abort_session_cleanup(&mut self) -> io::Result<()> {
    let ids = self.objects.keys().cloned().collect::<Vec<_>>();
    for id in ids {
      self.delete_object(&id)?;
    }
    Ok(())
  }

  fn stats(&self) -> MultiObjectStoreStats {
    self.stats
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileObjectMetadata {
  format_version: u32,
  invocation_id: String,
  descriptor: StateObjectDescriptor,
  byte_length: u64,
  chunk_count: u64,
  checksum: Option<[u8; 32]>,
  state: String,
  authentication_tag: [u8; 32],
}

#[derive(Debug)]
struct OpenFileObject {
  descriptor: StateObjectDescriptor,
  file: File,
  byte_length: u64,
  chunk_count: u64,
  sealed_checksum: Option<[u8; 32]>,
  temporary_data_name: String,
  final_data_name: String,
  final_manifest_name: String,
}

pub struct MultiObjectFileBackedStateStore {
  config: MultiObjectStoreConfig,
  root_directory: SecureDirectory,
  session_directory: SecureDirectory,
  session_root: PathBuf,
  objects: HashMap<String, OpenFileObject>,
  stats: MultiObjectStoreStats,
  current_bytes: u64,
  cleaned: bool,
}

pub(crate) struct VerifiedRangeReader {
  file: File,
  byte_length: u64,
}

impl MultiObjectFileBackedStateStore {
  pub fn create(config: MultiObjectStoreConfig) -> io::Result<Self> {
    let mut config = config;
    validate_config(&config)?;
    validate_name(&config.proof_session)?;
    if config.root.is_relative() {
      config.root = std::env::current_dir()?.join(&config.root);
    }
    let root_directory = SecureDirectory::prepare(&config.root)?;
    let session_directory = match root_directory.create_child_exclusive(&config.proof_session) {
      Ok(directory) => directory,
      Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
        let stale = root_directory.open_child(&config.proof_session)?;
        stale.cleanup_files_only()?;
        drop(stale);
        root_directory.remove_empty_child(&config.proof_session)?;
        root_directory.sync()?;
        return Err(io::Error::new(
          io::ErrorKind::AlreadyExists,
          "reused proof session was purged and rejected",
        ));
      }
      Err(error) => return Err(error),
    };
    root_directory.sync()?;
    let session_root = session_directory.path().to_path_buf();
    Ok(Self {
      config,
      root_directory,
      session_directory,
      session_root,
      objects: HashMap::new(),
      stats: MultiObjectStoreStats::default(),
      current_bytes: 0,
      cleaned: false,
    })
  }

  pub(crate) fn descriptor(
    &self,
    object_id: impl Into<String>,
    operator_id: impl Into<String>,
    element_type: impl Into<String>,
    logical_element_count: u64,
  ) -> StateObjectDescriptor {
    StateObjectDescriptor::canonical(
      object_id,
      &self.config.proof_session,
      &self.config.backend_revision,
      operator_id,
      element_type,
      logical_element_count,
      self.config.maximum_chunk_bytes,
    )
  }

  pub(crate) fn maximum_chunk_bytes(&self) -> usize {
    self.config.maximum_chunk_bytes
  }

  fn maybe_release_file_cache(&self, file: &File, offset: u64, length: u64) -> io::Result<()> {
    release_file_cache(file, offset, length)
  }

  fn data_path(&self, object_id: &str) -> PathBuf {
    self.session_root.join(format!("{object_id}.state"))
  }

  fn metadata_path(&self, object_id: &str) -> PathBuf {
    self.session_root.join(format!("{object_id}.meta"))
  }

  fn sealed_metadata(&self, object: &OpenFileObject) -> io::Result<FileObjectMetadata> {
    let mut metadata = FileObjectMetadata {
      format_version: FILE_FORMAT_VERSION,
      invocation_id: self.config.proof_session.clone(),
      descriptor: object.descriptor.clone(),
      byte_length: object.byte_length,
      chunk_count: object.chunk_count,
      checksum: object.sealed_checksum,
      state: "SEALED".to_owned(),
      authentication_tag: [0; 32],
    };
    metadata.authentication_tag = metadata_tag(&self.config.metadata_key, &metadata)?;
    Ok(metadata)
  }

  fn write_manifest_temporary(
    &self,
    object: &OpenFileObject,
    temporary_manifest_name: &str,
  ) -> io::Result<()> {
    let metadata = self.sealed_metadata(object)?;
    let encoded = bincode::serialize(&metadata)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = self
      .session_directory
      .create_file_exclusive(temporary_manifest_name)?;
    file.write_all(&encoded)?;
    file.sync_data()
  }

  fn verified_metadata(&self, object_id: &str) -> io::Result<FileObjectMetadata> {
    let manifest = self
      .session_directory
      .open_file(&format!("{object_id}.meta"), false)?;
    let mut encoded = Vec::new();
    manifest.take(1024 * 1024).read_to_end(&mut encoded)?;
    let metadata: FileObjectMetadata = bincode::deserialize(&encoded)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let expected = metadata_tag(&self.config.metadata_key, &metadata)?;
    if metadata.format_version != FILE_FORMAT_VERSION
      || metadata.state != "SEALED"
      || metadata.checksum.is_none()
      || metadata.invocation_id != self.config.proof_session
      || metadata.authentication_tag != expected
      || metadata.descriptor.object_id != object_id
      || metadata.descriptor.proof_session != self.config.proof_session
      || metadata.descriptor.backend_revision != self.config.backend_revision
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "metadata binding failure",
      ));
    }
    if metadata.descriptor.element_type == "Scalar"
      && metadata.descriptor.logical_element_count.checked_mul(32) != Some(metadata.byte_length)
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "manifest logical length mismatch",
      ));
    }
    Ok(metadata)
  }

  pub(crate) fn open_verified_range_reader(
    &self,
    object_id: &str,
  ) -> io::Result<VerifiedRangeReader> {
    let metadata = self.verified_metadata(object_id)?;
    if metadata.state != "SEALED" {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unsealed object",
      ));
    }
    let file = self
      .session_directory
      .open_file(&format!("{object_id}.state"), false)?;
    if file.metadata()?.len() != metadata.byte_length {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object truncation",
      ));
    }
    if checksum_open_file(&file, metadata.descriptor.chunk_size)?
      != metadata.checksum.expect("checked above")
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object checksum mismatch",
      ));
    }
    Ok(VerifiedRangeReader {
      file,
      byte_length: metadata.byte_length,
    })
  }

  pub(crate) fn read_verified_range(
    &mut self,
    reader: &mut VerifiedRangeReader,
    offset: u64,
    length: usize,
  ) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    if offset + length as u64 > reader.byte_length {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "range outside sealed object",
      ));
    }
    reader.file.seek(SeekFrom::Start(offset))?;
    let mut output = vec![0u8; length];
    reader.file.read_exact(&mut output)?;
    self.stats.bytes_read += length as u64;
    self.stats.range_reads += 1;
    self.stats.range_read_bytes = self.stats.range_read_bytes.saturating_add(length as u64);
    self.stats.seek_calls = self.stats.seek_calls.saturating_add(1);
    self.stats.largest_read_bytes = self.stats.largest_read_bytes.max(length as u64);
    self.maybe_release_file_cache(&reader.file, offset, length as u64)?;
    self.stats.read_time_ns = self
      .stats
      .read_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(output)
  }
}

impl ProverStateStore for MultiObjectFileBackedStateStore {
  fn create_object(&mut self, descriptor: StateObjectDescriptor) -> io::Result<()> {
    let started = Instant::now();
    validate_descriptor(&self.config, &descriptor)?;
    validate_object_id(&descriptor.object_id)?;
    if self.objects.contains_key(&descriptor.object_id) {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "duplicate object",
      ));
    }
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary_data_name = format!("{}.state.{nonce}.tmp", descriptor.object_id);
    let final_data_name = format!("{}.state", descriptor.object_id);
    let final_manifest_name = format!("{}.meta", descriptor.object_id);
    if self.session_directory.entry_exists(&final_data_name)?
      || self.session_directory.entry_exists(&final_manifest_name)?
    {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "spill target already exists",
      ));
    }
    #[cfg(feature = "thinwallet-experiment")]
    let data_path = self.session_root.join(&temporary_data_name);
    let file = self
      .session_directory
      .create_file_exclusive(&temporary_data_name)?;
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::register_temp_artifact(&data_path, artifact_category(&data_path));
    let object = OpenFileObject {
      descriptor: descriptor.clone(),
      file,
      byte_length: 0,
      chunk_count: 0,
      sealed_checksum: None,
      temporary_data_name,
      final_data_name,
      final_manifest_name,
    };
    self.objects.insert(descriptor.object_id.clone(), object);
    self.stats.objects_created = self.stats.objects_created.saturating_add(1);
    self.stats.write_time_ns = self
      .stats
      .write_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(())
  }

  fn append_chunk(&mut self, object_id: &str, chunk_index: u64, data: &[u8]) -> io::Result<()> {
    let started = Instant::now();
    #[cfg(feature = "thinwallet-experiment")]
    let artifact_path = self
      .objects
      .get(object_id)
      .map(|object| self.session_root.join(&object.temporary_data_name))
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    let object = self
      .objects
      .get_mut(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    validate_append(
      &self.config,
      &object.descriptor,
      object.chunk_count,
      chunk_index,
      data,
    )?;
    if object.sealed_checksum.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "sealed object",
      ));
    }
    let next = self.current_bytes + data.len() as u64;
    if next > self.config.maximum_temporary_storage_bytes {
      return Err(io::Error::new(
        io::ErrorKind::OutOfMemory,
        "temporary storage budget exceeded",
      ));
    }
    object.file.seek(SeekFrom::End(0))?;
    object.file.write_all(data)?;
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_artifact_write(&artifact_path, data.len() as u64);
    object.byte_length += data.len() as u64;
    object.chunk_count += 1;
    self.current_bytes = next;
    self.stats.bytes_written += data.len() as u64;
    self.stats.append_calls = self.stats.append_calls.saturating_add(1);
    self.stats.seek_calls = self.stats.seek_calls.saturating_add(1);
    self.stats.data_write_calls = self.stats.data_write_calls.saturating_add(1);
    self.stats.largest_write_bytes = self.stats.largest_write_bytes.max(data.len() as u64);
    self.stats.temporary_storage_peak_bytes = self.stats.temporary_storage_peak_bytes.max(next);
    self.stats.write_time_ns = self
      .stats
      .write_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(())
  }

  fn seal_object(&mut self, object_id: &str) -> io::Result<[u8; 32]> {
    let object = self
      .objects
      .get_mut(object_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown object"))?;
    if object.sealed_checksum.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "object already sealed",
      ));
    }
    let fsync_started = Instant::now();
    object.file.sync_data()?;
    self.stats.fsync_time_ns = self
      .stats
      .fsync_time_ns
      .saturating_add(fsync_started.elapsed().as_nanos() as u64);
    self.stats.fsync_calls = self.stats.fsync_calls.saturating_add(1);
    self.stats.sync_data_calls = self.stats.sync_data_calls.saturating_add(1);

    let checksum_started = Instant::now();
    let checksum = checksum_open_file(&object.file, self.config.maximum_chunk_bytes)?;
    self.stats.read_time_ns = self
      .stats
      .read_time_ns
      .saturating_add(checksum_started.elapsed().as_nanos() as u64);
    release_file_cache(&object.file, 0, object.byte_length)?;
    object.sealed_checksum = Some(checksum);
    let descriptor_id = object.descriptor.object_id.clone();
    let _ = object;
    let object = self.objects.get(&descriptor_id).unwrap();
    let manifest_nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary_manifest_name = format!("{descriptor_id}.meta.{manifest_nonce}.tmp");
    self.write_manifest_temporary(object, &temporary_manifest_name)?;
    self
      .session_directory
      .rename(&object.temporary_data_name, &object.final_data_name)?;
    self
      .session_directory
      .rename(&temporary_manifest_name, &object.final_manifest_name)?;
    self.session_directory.sync()?;
    self.stats.seal_calls = self.stats.seal_calls.saturating_add(1);
    self.stats.metadata_write_calls = self.stats.metadata_write_calls.saturating_add(1);
    self.stats.fsync_calls = self.stats.fsync_calls.saturating_add(2);
    Ok(checksum)
  }

  fn sequential_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    let started = Instant::now();
    let metadata = self.verified_metadata(object_id)?;
    let expected = metadata
      .checksum
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsealed object"))?;
    let mut file = self
      .session_directory
      .open_file(&format!("{object_id}.state"), false)?;
    if file.metadata()?.len() != metadata.byte_length {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object truncation",
      ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; metadata.descriptor.chunk_size];
    for index in 0..metadata.chunk_count {
      let remaining = metadata.byte_length - index * metadata.descriptor.chunk_size as u64;
      let length = (remaining as usize).min(buffer.len());
      file.read_exact(&mut buffer[..length])?;
      hasher.update(&buffer[..length]);
      visitor(index, &buffer[..length])?;
      self.stats.bytes_read += length as u64;
      self.stats.largest_read_bytes = self.stats.largest_read_bytes.max(length as u64);
      buffer[..length].fill(0);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object checksum mismatch",
      ));
    }
    self.stats.full_scans += 1;
    self.maybe_release_file_cache(&file, 0, metadata.byte_length)?;
    self.stats.read_time_ns = self
      .stats
      .read_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(())
  }

  fn range_read(&mut self, object_id: &str, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let metadata = self.verified_metadata(object_id)?;
    if metadata.state != "SEALED" || offset + length as u64 > metadata.byte_length {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "range outside sealed object",
      ));
    }
    let mut file = self
      .session_directory
      .open_file(&format!("{object_id}.state"), false)?;
    let expected = metadata
      .checksum
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsealed object"))?;
    if checksum_open_file(&file, metadata.descriptor.chunk_size)? != expected {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "object checksum mismatch",
      ));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut output = vec![0u8; length];
    file.read_exact(&mut output)?;
    self.stats.bytes_read += length as u64;
    self.stats.range_reads += 1;
    self.stats.range_read_bytes = self.stats.range_read_bytes.saturating_add(length as u64);
    self.stats.seek_calls = self.stats.seek_calls.saturating_add(1);
    self.stats.largest_read_bytes = self.stats.largest_read_bytes.max(length as u64);
    self.maybe_release_file_cache(&file, offset, length as u64)?;
    self.stats.read_time_ns = self
      .stats
      .read_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(output)
  }

  fn replay_scan(
    &mut self,
    object_id: &str,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    self.sequential_scan(object_id, visitor)?;
    self.stats.replay_scans += 1;
    Ok(())
  }

  fn delete_object(&mut self, object_id: &str) -> io::Result<()> {
    let started = Instant::now();
    #[cfg(feature = "thinwallet-experiment")]
    let temporary_path = self
      .objects
      .get(object_id)
      .map(|object| self.session_root.join(&object.temporary_data_name));
    if let Some(object) = self.objects.remove(object_id) {
      self.current_bytes = self.current_bytes.saturating_sub(object.byte_length);
      let _ = object.file.set_len(0);
      self
        .session_directory
        .remove_file(&object.temporary_data_name)?;
      self
        .session_directory
        .remove_file(&object.final_data_name)?;
      self
        .session_directory
        .remove_file(&object.final_manifest_name)?;
    }
    self.stats.objects_deleted = self.stats.objects_deleted.saturating_add(1);
    #[cfg(feature = "thinwallet-experiment")]
    {
      let data_path = self.data_path(object_id);
      let metadata_path = self.metadata_path(object_id);
      if let Some(temporary_path) = temporary_path {
        thinwallet_instrumentation::record_artifact_truncate(&temporary_path);
        thinwallet_instrumentation::record_artifact_remove(&temporary_path);
      }
      thinwallet_instrumentation::record_artifact_remove(&data_path);
      thinwallet_instrumentation::record_artifact_remove(&metadata_path);
    }
    self
      .session_directory
      .remove_file(&format!("{object_id}.state"))?;
    self
      .session_directory
      .remove_file(&format!("{object_id}.meta"))?;
    self.stats.cleanup_time_ns = self
      .stats
      .cleanup_time_ns
      .saturating_add(started.elapsed().as_nanos() as u64);
    Ok(())
  }

  fn abort_session_cleanup(&mut self) -> io::Result<()> {
    let ids = self.objects.keys().cloned().collect::<Vec<_>>();
    for id in ids {
      self.delete_object(&id)?;
    }
    self.objects.clear();
    self.session_directory.cleanup_files_only()?;
    self
      .root_directory
      .remove_empty_child(&self.config.proof_session)?;
    self.root_directory.sync()?;
    self.cleaned = true;
    Ok(())
  }

  fn stats(&self) -> MultiObjectStoreStats {
    self.stats
  }
}

impl Drop for MultiObjectFileBackedStateStore {
  fn drop(&mut self) {
    let _ = self.abort_session_cleanup();
  }
}

pub struct ReadOnlyMmapStateStore {
  descriptor: StateObjectDescriptor,
  map: Mmap,
  checksum: [u8; 32],
  stats: MultiObjectStoreStats,
}

impl ReadOnlyMmapStateStore {
  pub fn open(store: &MultiObjectFileBackedStateStore, object_id: &str) -> io::Result<Self> {
    let metadata = store.verified_metadata(object_id)?;
    let checksum = metadata
      .checksum
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsealed object"))?;
    let file = store
      .session_directory
      .open_file(&format!("{object_id}.state"), false)?;
    let map = unsafe { MmapOptions::new().map(&file)? };
    if map.len() as u64 != metadata.byte_length || Sha256::digest(&map[..]).as_slice() != checksum {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "mapped object integrity failure",
      ));
    }
    Ok(Self {
      descriptor: metadata.descriptor,
      map,
      checksum,
      stats: MultiObjectStoreStats::default(),
    })
  }

  pub fn sequential_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    if Sha256::digest(&self.map[..]).as_slice() != self.checksum {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "mapped object checksum mismatch",
      ));
    }
    for (index, chunk) in self.map.chunks(self.descriptor.chunk_size).enumerate() {
      visitor(index as u64, chunk)?;
      self.stats.bytes_read += chunk.len() as u64;
    }
    self.stats.full_scans += 1;
    Ok(())
  }
}

pub struct RecomputeStateSource<F>
where
  F: FnMut(&mut dyn FnMut(u64, &[u8]) -> io::Result<()>) -> io::Result<()>,
{
  pub descriptor: StateObjectDescriptor,
  producer: F,
  pub replay_count: u64,
}

impl<F> RecomputeStateSource<F>
where
  F: FnMut(&mut dyn FnMut(u64, &[u8]) -> io::Result<()>) -> io::Result<()>,
{
  pub fn new(descriptor: StateObjectDescriptor, producer: F) -> Self {
    Self {
      descriptor,
      producer,
      replay_count: 0,
    }
  }

  pub fn replay_scan(
    &mut self,
    visitor: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
  ) -> io::Result<()> {
    (self.producer)(visitor)?;
    self.replay_count += 1;
    Ok(())
  }
}

fn validate_config(config: &MultiObjectStoreConfig) -> io::Result<()> {
  if config.maximum_chunk_bytes == 0 || config.maximum_temporary_storage_bytes == 0 {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "zero store bound",
    ));
  }
  Ok(())
}

fn validate_descriptor(
  config: &MultiObjectStoreConfig,
  descriptor: &StateObjectDescriptor,
) -> io::Result<()> {
  validate_object_id(&descriptor.object_id)?;
  if descriptor.proof_session != config.proof_session
    || descriptor.backend_revision != config.backend_revision
    || descriptor.chunk_size == 0
    || descriptor.chunk_size > config.maximum_chunk_bytes
    || descriptor.canonical_encoding_version != ENCODING_VERSION
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "invalid object binding",
    ));
  }
  Ok(())
}

fn validate_append(
  config: &MultiObjectStoreConfig,
  descriptor: &StateObjectDescriptor,
  expected_index: u64,
  chunk_index: u64,
  data: &[u8],
) -> io::Result<()> {
  if chunk_index != expected_index
    || data.is_empty()
    || data.len() > descriptor.chunk_size
    || data.len() > config.maximum_chunk_bytes
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "non-canonical chunk",
    ));
  }
  Ok(())
}

fn validate_object_id(value: &str) -> io::Result<()> {
  if value.is_empty()
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "unsafe object id",
    ));
  }
  Ok(())
}

fn metadata_tag(key: &[u8; 32], metadata: &FileObjectMetadata) -> io::Result<[u8; 32]> {
  let mut unsigned = metadata.clone();
  unsigned.authentication_tag = [0; 32];
  let bytes = bincode::serialize(&unsigned)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
  let mut hasher = Sha256::new();
  hasher.update(key);
  hasher.update(bytes);
  Ok(hasher.finalize().into())
}

fn checksum_chunks(chunks: &[Vec<u8>]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  for chunk in chunks {
    hasher.update(chunk);
  }
  hasher.finalize().into()
}

fn checksum_open_file(file: &File, chunk_size: usize) -> io::Result<[u8; 32]> {
  let mut file = file.try_clone()?;
  file.seek(SeekFrom::Start(0))?;
  let mut buffer = vec![0u8; chunk_size];
  let mut hasher = Sha256::new();
  loop {
    let read = file.read(&mut buffer)?;
    if read == 0 {
      break;
    }
    hasher.update(&buffer[..read]);
    buffer[..read].fill(0);
  }
  Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;

  fn config(name: &str) -> MultiObjectStoreConfig {
    MultiObjectStoreConfig {
      root: std::env::temp_dir().join(format!("v3b-{name}-{}", std::process::id())),
      proof_session: name.to_owned(),
      backend_revision: "libspartan-0.9.0-v3b".to_owned(),
      metadata_key: [0x55; 32],
      maximum_chunk_bytes: 4,
      maximum_temporary_storage_bytes: 64,
      durability: StateDurability::SecurityCriticalDurable,
    }
  }

  fn descriptor(config: &MultiObjectStoreConfig, id: &str) -> StateObjectDescriptor {
    StateObjectDescriptor::canonical(
      id,
      &config.proof_session,
      &config.backend_revision,
      "SumcheckFold",
      "Bytes",
      6,
      4,
    )
  }

  #[test]
  fn file_store_rejects_truncation_reordering_and_cross_session_swap() {
    let file_config = config("file-security");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap();
    assert!(store.append_chunk("layer", 1, b"bad").is_err());
    store.append_chunk("layer", 0, b"abcd").unwrap();
    store.append_chunk("layer", 1, b"ef").unwrap();
    store.seal_object("layer").unwrap();
    let mut output = Vec::new();
    store
      .sequential_scan("layer", &mut |_, bytes| {
        output.extend_from_slice(bytes);
        Ok(())
      })
      .unwrap();
    assert_eq!(output, b"abcdef");

    fs::write(store.data_path("layer"), b"abcdeg").unwrap();
    assert!(store.sequential_scan("layer", &mut |_, _| Ok(())).is_err());
    fs::write(store.data_path("layer"), b"abcdef").unwrap();

    std::fs::OpenOptions::new()
      .write(true)
      .open(store.data_path("layer"))
      .unwrap()
      .set_len(3)
      .unwrap();
    assert!(store.sequential_scan("layer", &mut |_, _| Ok(())).is_err());

    let swapped = config("other-session");
    let metadata = fs::read(store.metadata_path("layer")).unwrap();
    fs::create_dir_all(swapped.root.join(&swapped.proof_session)).unwrap();
    fs::write(
      swapped.root.join(&swapped.proof_session).join("layer.meta"),
      metadata,
    )
    .unwrap();
    fs::write(
      swapped
        .root
        .join(&swapped.proof_session)
        .join("layer.state"),
      b"abcdef",
    )
    .unwrap();
    let error = match MultiObjectFileBackedStateStore::create(swapped) {
      Ok(_) => panic!("stale session was accepted"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
  }

  #[test]
  fn memory_store_enforces_storage_bound_and_cleanup() {
    let mut config = config("memory");
    config.maximum_temporary_storage_bytes = 4;
    let mut store = MultiObjectInMemoryStateStore::create(config.clone()).unwrap();
    store.create_object(descriptor(&config, "a")).unwrap();
    store.append_chunk("a", 0, b"abcd").unwrap();
    store.create_object(descriptor(&config, "b")).unwrap();
    assert_eq!(
      store.append_chunk("b", 0, b"z").unwrap_err().kind(),
      io::ErrorKind::OutOfMemory
    );
    store.seal_object("a").unwrap();
    assert_eq!(store.range_read("a", 1, 2).unwrap(), b"bc");
    store.abort_session_cleanup().unwrap();
    assert_eq!(store.current_bytes, 0);
  }

  #[test]
  fn ephemeral_store_still_uses_fail_stop_fsync() {
    let mut ephemeral = config("ephemeral");
    ephemeral.durability = StateDurability::EphemeralCorrectnessOnly;
    std::env::set_var("THINWALLET_SERVER_FILE_STORE", "1");
    let mut store = MultiObjectFileBackedStateStore::create(ephemeral.clone()).unwrap();
    store
      .create_object(descriptor(&ephemeral, "checkpoint"))
      .unwrap();
    store.append_chunk("checkpoint", 0, b"abcd").unwrap();
    store.seal_object("checkpoint").unwrap();
    let stats = store.stats();
    assert!(stats.fsync_calls >= 3);
    assert_eq!(stats.sync_data_calls, 1);
    assert_eq!(stats.skipped_fsync_calls, 0);
    let mut output = Vec::new();
    store
      .sequential_scan("checkpoint", &mut |_, bytes| {
        output.extend_from_slice(bytes);
        Ok(())
      })
      .unwrap();
    assert_eq!(output, b"abcd");
    std::env::remove_var("THINWALLET_SERVER_FILE_STORE");
  }

  fn assert_crash_state_is_purged_and_never_resumed(file_config: MultiObjectStoreConfig) {
    let root = file_config.root.clone();
    let session = file_config.proof_session.clone();
    let error = match MultiObjectFileBackedStateStore::create(file_config.clone()) {
      Ok(_) => panic!("crash state was resumed"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(!root.join(&session).exists());

    let mut fresh = MultiObjectFileBackedStateStore::create(file_config).unwrap();
    assert!(fresh.verified_metadata("layer").is_err());
    fresh.abort_session_cleanup().unwrap();
  }

  #[test]
  fn crash_after_payload_creation_before_seal_is_fail_stop() {
    let file_config = config("crash-payload-created");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap();
    std::mem::forget(store);
    assert_crash_state_is_purged_and_never_resumed(file_config);
  }

  #[test]
  fn crash_after_payload_fsync_before_manifest_is_fail_stop() {
    let file_config = config("crash-payload-fsync");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap();
    store.append_chunk("layer", 0, b"abcd").unwrap();
    store
      .objects
      .get("layer")
      .unwrap()
      .file
      .sync_data()
      .unwrap();
    std::mem::forget(store);
    assert_crash_state_is_purged_and_never_resumed(file_config);
  }

  #[test]
  fn crash_after_manifest_write_before_rename_is_fail_stop() {
    let file_config = config("crash-manifest-written");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap();
    store.append_chunk("layer", 0, b"abcd").unwrap();
    let object = store.objects.get_mut("layer").unwrap();
    object.file.sync_data().unwrap();
    object.sealed_checksum = Some(checksum_open_file(&object.file, 4).unwrap());
    store
      .write_manifest_temporary(store.objects.get("layer").unwrap(), "layer.meta.crash.tmp")
      .unwrap();
    std::mem::forget(store);
    assert_crash_state_is_purged_and_never_resumed(file_config);
  }

  #[test]
  fn crash_after_rename_before_parent_fsync_is_fail_stop() {
    let file_config = config("crash-before-parent-fsync");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap();
    store.append_chunk("layer", 0, b"abcd").unwrap();
    let object = store.objects.get_mut("layer").unwrap();
    object.file.sync_data().unwrap();
    object.sealed_checksum = Some(checksum_open_file(&object.file, 4).unwrap());
    store
      .write_manifest_temporary(store.objects.get("layer").unwrap(), "layer.meta.crash.tmp")
      .unwrap();
    let object = store.objects.get("layer").unwrap();
    store
      .session_directory
      .rename(&object.temporary_data_name, &object.final_data_name)
      .unwrap();
    store
      .session_directory
      .rename("layer.meta.crash.tmp", &object.final_manifest_name)
      .unwrap();
    std::mem::forget(store);
    assert_crash_state_is_purged_and_never_resumed(file_config);
  }

  #[cfg(unix)]
  #[test]
  fn spill_target_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let file_config = config("symlink-target");
    let mut store = MultiObjectFileBackedStateStore::create(file_config.clone()).unwrap();
    let outside = file_config.root.join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, store.data_path("layer")).unwrap();
    let error = store
      .create_object(descriptor(&file_config, "layer"))
      .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    store.abort_session_cleanup().unwrap();
    fs::remove_file(outside).unwrap();
  }
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
