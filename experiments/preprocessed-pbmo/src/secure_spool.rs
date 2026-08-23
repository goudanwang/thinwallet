//! Fail-stop storage for the malicious-mode PBMO request spool.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const FORMAT_VERSION: u16 = 1;
const ENCODING: &str = "ristretto-scalar-canonical-v1";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SpoolDescriptor {
    pub(crate) invocation_id: String,
    pub(crate) object_id: String,
    pub(crate) context_digest: [u8; 32],
    pub(crate) logical_element_count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpoolManifest {
    format_version: u16,
    invocation_id: String,
    object_id: String,
    operator_tag: String,
    type_tag: String,
    context_digest: [u8; 32],
    logical_element_count: u64,
    byte_length: u64,
    chunk_size_bytes: u64,
    encoding: String,
    checksum_sha256: [u8; 32],
    state: String,
}

#[derive(Debug)]
struct SecureDirectory {
    path: PathBuf,
    file: File,
}

impl SecureDirectory {
    fn prepare(path: &Path) -> io::Result<Self> {
        let existed = path.exists();
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Self::open(path)
    }

    fn open(path: &Path) -> io::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        #[cfg(unix)]
        let file = open_absolute_directory_no_symlinks(&absolute)?;
        #[cfg(not(unix))]
        let file = {
            if fs::symlink_metadata(&absolute)?.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "temporary root must not be a symlink",
                ));
            }
            File::open(&absolute)?
        };
        Ok(Self {
            path: absolute,
            file,
        })
    }

    fn create_file_exclusive(&self, name: &str) -> io::Result<File> {
        validate_name(name)?;
        #[cfg(unix)]
        {
            let encoded = c_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    encoded.as_ptr(),
                    libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_RDWR
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        #[cfg(not(unix))]
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(self.path.join(name))
    }

    fn open_file(&self, name: &str) -> io::Result<File> {
        validate_name(name)?;
        #[cfg(unix)]
        {
            let encoded = c_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    encoded.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        #[cfg(not(unix))]
        OpenOptions::new().read(true).open(self.path.join(name))
    }

    fn entry_exists(&self, name: &str) -> io::Result<bool> {
        validate_name(name)?;
        #[cfg(unix)]
        {
            let encoded = c_name(name)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    encoded.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        }
        #[cfg(not(unix))]
        match fs::symlink_metadata(self.path.join(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate_name(from)?;
        validate_name(to)?;
        if self.entry_exists(to)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace an existing sealed spool object",
            ));
        }
        #[cfg(unix)]
        {
            let from = c_name(from)?;
            let to = c_name(to)?;
            let result = unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    from.as_ptr(),
                    self.file.as_raw_fd(),
                    to.as_ptr(),
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        fs::rename(self.path.join(from), self.path.join(to))
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        validate_name(name)?;
        #[cfg(unix)]
        {
            let encoded = c_name(name)?;
            let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), encoded.as_ptr(), 0) };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        }
        #[cfg(not(unix))]
        match fs::remove_file(self.path.join(name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[derive(Debug)]
pub(crate) struct SecureSpool {
    directory: SecureDirectory,
    descriptor: SpoolDescriptor,
    temp_name: String,
    final_name: String,
    manifest_temp_name: String,
    manifest_name: String,
    payload: Option<File>,
    written_elements: u64,
    sealed: bool,
}

impl SecureSpool {
    pub(crate) fn create(path: &Path, descriptor: SpoolDescriptor) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "spool path has no parent")
        })?;
        let final_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid spool name"))?
            .to_owned();
        validate_name(&final_name)?;
        let directory = SecureDirectory::prepare(parent)?;
        let manifest_name = format!("{final_name}.manifest");
        if directory.entry_exists(&final_name)? || directory.entry_exists(&manifest_name)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "stale or reused PBMO spool object rejected",
            ));
        }
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(".{final_name}.{}.{nonce}.tmp", std::process::id());
        let manifest_temp_name = format!(".{manifest_name}.{}.{nonce}.tmp", std::process::id());
        let payload = directory.create_file_exclusive(&temp_name)?;
        Ok(Self {
            directory,
            descriptor,
            temp_name,
            final_name,
            manifest_temp_name,
            manifest_name,
            payload: Some(payload),
            written_elements: 0,
            sealed: false,
        })
    }

    pub(crate) fn append(&mut self, scalars: &[[u8; 32]]) -> io::Result<()> {
        if self.sealed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot append to sealed PBMO spool",
            ));
        }
        let payload = self.payload.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "PBMO spool payload unavailable")
        })?;
        for scalar in scalars {
            payload.write_all(scalar)?;
        }
        self.written_elements += scalars.len() as u64;
        Ok(())
    }

    pub(crate) fn seal_and_open_verified(&mut self) -> io::Result<File> {
        if self.sealed {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "PBMO spool already sealed",
            ));
        }
        if self.written_elements != self.descriptor.logical_element_count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "PBMO spool logical element count mismatch",
            ));
        }
        let payload = self.payload.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "PBMO spool payload unavailable")
        })?;
        payload.sync_data()?;
        drop(payload);

        let byte_length = self.written_elements.checked_mul(32).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "PBMO spool length overflow")
        })?;
        let checksum = hash_file(&mut self.directory.open_file(&self.temp_name)?)?;
        let manifest = SpoolManifest {
            format_version: FORMAT_VERSION,
            invocation_id: self.descriptor.invocation_id.clone(),
            object_id: self.descriptor.object_id.clone(),
            operator_tag: "pbmo_aggregate_check".into(),
            type_tag: "Scalar".into(),
            context_digest: self.descriptor.context_digest,
            logical_element_count: self.written_elements,
            byte_length,
            chunk_size_bytes: 32,
            encoding: ENCODING.into(),
            checksum_sha256: checksum,
            state: "SEALED".into(),
        };
        let encoded = bincode::serialize(&manifest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut manifest_file = self
            .directory
            .create_file_exclusive(&self.manifest_temp_name)?;
        manifest_file.write_all(&encoded)?;
        manifest_file.sync_data()?;
        drop(manifest_file);

        self.directory.rename(&self.temp_name, &self.final_name)?;
        self.directory
            .rename(&self.manifest_temp_name, &self.manifest_name)?;
        self.directory.sync()?;
        self.sealed = true;
        self.open_verified()
    }

    fn open_verified(&self) -> io::Result<File> {
        let mut manifest_file = self.directory.open_file(&self.manifest_name)?;
        let mut encoded = Vec::new();
        manifest_file.read_to_end(&mut encoded)?;
        let manifest: SpoolManifest = bincode::deserialize(&encoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let expected_bytes = self
            .descriptor
            .logical_element_count
            .checked_mul(32)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "spool length overflow"))?;
        if manifest.format_version != FORMAT_VERSION
            || manifest.invocation_id != self.descriptor.invocation_id
            || manifest.object_id != self.descriptor.object_id
            || manifest.operator_tag != "pbmo_aggregate_check"
            || manifest.type_tag != "Scalar"
            || manifest.context_digest != self.descriptor.context_digest
            || manifest.logical_element_count != self.descriptor.logical_element_count
            || manifest.byte_length != expected_bytes
            || manifest.chunk_size_bytes != 32
            || manifest.encoding != ENCODING
            || manifest.state != "SEALED"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PBMO spool manifest does not match the active invocation",
            ));
        }
        let mut payload = self.directory.open_file(&self.final_name)?;
        if payload.metadata()?.len() != expected_bytes
            || hash_file(&mut payload)? != manifest.checksum_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PBMO spool payload is incomplete or checksum-invalid",
            ));
        }
        payload.seek(SeekFrom::Start(0))?;
        Ok(payload)
    }

    pub(crate) fn active_path(&self) -> PathBuf {
        self.directory.path.join(if self.sealed {
            &self.final_name
        } else {
            &self.temp_name
        })
    }

    pub(crate) fn remove(&mut self) -> io::Result<()> {
        self.payload.take();
        self.directory.remove_file(&self.temp_name)?;
        self.directory.remove_file(&self.manifest_temp_name)?;
        self.directory.remove_file(&self.final_name)?;
        self.directory.remove_file(&self.manifest_name)?;
        self.directory.sync()?;
        self.sealed = false;
        Ok(())
    }
}

impl Drop for SecureSpool {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

fn hash_file(file: &mut File) -> io::Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe PBMO spool object name",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn c_name(name: &str) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in object name"))
}

#[cfg(unix)]
fn c_os_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path component"))
}

#[cfg(unix)]
fn open_absolute_directory_no_symlinks(path: &Path) -> io::Result<File> {
    let root = CString::new("/").unwrap();
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = unsafe { File::from_raw_fd(root_fd) };
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "temporary root contains traversal",
                ));
            }
        };
        let name = c_os_name(name)?;
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> SpoolDescriptor {
        SpoolDescriptor {
            invocation_id: "invocation-a".into(),
            object_id: "proof-a".into(),
            context_digest: [7; 32],
            logical_element_count: 2,
        }
    }

    #[test]
    fn seals_verifies_and_deletes_spool() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("request.spool");
        let mut spool = SecureSpool::create(&path, descriptor()).unwrap();
        spool.append(&[[1; 32], [2; 32]]).unwrap();
        let mut reader = spool.seal_and_open_verified().unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64);
        spool.remove().unwrap();
        assert!(!path.exists());
        assert!(!path.with_file_name("request.spool.manifest").exists());
    }

    #[test]
    fn rejects_reuse_and_traversal() {
        assert!(validate_name("../request.spool").is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("request.spool");
        fs::write(&path, b"stale").unwrap();
        assert!(SecureSpool::create(&path, descriptor()).is_err());
    }
}
