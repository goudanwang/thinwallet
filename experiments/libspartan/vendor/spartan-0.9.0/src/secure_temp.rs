//! Directory-FD-confined temporary file operations.

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

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

#[derive(Debug)]
pub(crate) struct SecureDirectory {
  path: PathBuf,
  file: File,
}

impl SecureDirectory {
  pub(crate) fn prepare(path: &Path) -> io::Result<Self> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    if !existed {
      fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Self::open(path)
  }

  pub(crate) fn open(path: &Path) -> io::Result<Self> {
    if !path.is_absolute() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "secure temporary root must be absolute",
      ));
    }

    #[cfg(unix)]
    let file = open_absolute_directory_no_symlinks(path)?;
    #[cfg(not(unix))]
    let file = {
      if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
          io::ErrorKind::InvalidInput,
          "temporary root must not be a symlink",
        ));
      }
      File::open(path)?
    };

    Ok(Self {
      path: path.to_path_buf(),
      file,
    })
  }

  pub(crate) fn create_child_exclusive(&self, name: &str) -> io::Result<Self> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let result = unsafe { libc::mkdirat(self.file.as_raw_fd(), encoded.as_ptr(), 0o700) };
      if result != 0 {
        return Err(io::Error::last_os_error());
      }
      let fd = unsafe {
        libc::openat(
          self.file.as_raw_fd(),
          encoded.as_ptr(),
          libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
      };
      if fd < 0 {
        return Err(io::Error::last_os_error());
      }
      return Ok(Self {
        path: self.path.join(name),
        file: unsafe { File::from_raw_fd(fd) },
      });
    }

    #[cfg(not(unix))]
    {
      let path = self.path.join(name);
      fs::create_dir(&path)?;
      Self::open(&path)
    }
  }

  pub(crate) fn open_child(&self, name: &str) -> io::Result<Self> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let fd = unsafe {
        libc::openat(
          self.file.as_raw_fd(),
          encoded.as_ptr(),
          libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
      };
      if fd < 0 {
        return Err(io::Error::last_os_error());
      }
      return Ok(Self {
        path: self.path.join(name),
        file: unsafe { File::from_raw_fd(fd) },
      });
    }

    #[cfg(not(unix))]
    Self::open(&self.path.join(name))
  }

  pub(crate) fn create_file_exclusive(&self, name: &str) -> io::Result<File> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let fd = unsafe {
        libc::openat(
          self.file.as_raw_fd(),
          encoded.as_ptr(),
          libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
          0o600,
        )
      };
      if fd < 0 {
        return Err(io::Error::last_os_error());
      }
      return Ok(unsafe { File::from_raw_fd(fd) });
    }

    #[cfg(not(unix))]
    OpenOptions::new()
      .create_new(true)
      .read(true)
      .write(true)
      .open(self.path.join(name))
  }

  pub(crate) fn open_file(&self, name: &str, writable: bool) -> io::Result<File> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let access = if writable {
        libc::O_RDWR
      } else {
        libc::O_RDONLY
      };
      let fd = unsafe {
        libc::openat(
          self.file.as_raw_fd(),
          encoded.as_ptr(),
          access | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
      };
      if fd < 0 {
        return Err(io::Error::last_os_error());
      }
      return Ok(unsafe { File::from_raw_fd(fd) });
    }

    #[cfg(not(unix))]
    OpenOptions::new()
      .read(true)
      .write(writable)
      .open(self.path.join(name))
  }

  pub(crate) fn entry_exists(&self, name: &str) -> io::Result<bool> {
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
      return if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
      } else {
        Err(error)
      };
    }

    #[cfg(not(unix))]
    match fs::symlink_metadata(self.path.join(name)) {
      Ok(_) => Ok(true),
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
      Err(error) => Err(error),
    }
  }

  pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
    validate_name(from)?;
    validate_name(to)?;
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
      return Ok(());
    }

    #[cfg(not(unix))]
    fs::rename(self.path.join(from), self.path.join(to))
  }

  pub(crate) fn remove_file(&self, name: &str) -> io::Result<()> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), encoded.as_ptr(), 0) };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      return if error.kind() == io::ErrorKind::NotFound {
        Ok(())
      } else {
        Err(error)
      };
    }

    #[cfg(not(unix))]
    match fs::remove_file(self.path.join(name)) {
      Ok(()) => Ok(()),
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
      Err(error) => Err(error),
    }
  }

  pub(crate) fn remove_empty_child(&self, name: &str) -> io::Result<()> {
    validate_name(name)?;
    #[cfg(unix)]
    {
      let encoded = c_name(name)?;
      let result =
        unsafe { libc::unlinkat(self.file.as_raw_fd(), encoded.as_ptr(), libc::AT_REMOVEDIR) };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      return if error.kind() == io::ErrorKind::NotFound {
        Ok(())
      } else {
        Err(error)
      };
    }

    #[cfg(not(unix))]
    match fs::remove_dir(self.path.join(name)) {
      Ok(()) => Ok(()),
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
      Err(error) => Err(error),
    }
  }

  pub(crate) fn sync(&self) -> io::Result<()> {
    self.file.sync_all()
  }

  pub(crate) fn path(&self) -> &Path {
    &self.path
  }

  pub(crate) fn cleanup_files_only(&self) -> io::Result<()> {
    for entry in fs::read_dir(&self.path)? {
      let entry = entry?;
      let metadata = fs::symlink_metadata(entry.path())?;
      if metadata.is_dir() && !metadata.file_type().is_symlink() {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "refusing recursive cleanup of unknown directory",
        ));
      }
      let name = entry
        .file_name()
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 spill name"))?;
      self.remove_file(&name)?;
    }
    self.sync()
  }
}

pub(crate) fn validate_name(name: &str) -> io::Result<()> {
  if name.is_empty()
    || name == "."
    || name == ".."
    || name.contains('/')
    || name.contains('\\')
    || name.as_bytes().contains(&0)
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "unsafe temporary object name",
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

  #[test]
  fn rejects_traversal_and_symlink_roots() {
    assert!(validate_name("../escape").is_err());
    assert!(validate_name("nested/object").is_err());

    #[cfg(unix)]
    {
      use std::os::unix::fs::symlink;
      let base = std::env::temp_dir().join(format!("thinwallet-secure-{}", std::process::id()));
      let _ = fs::remove_dir_all(&base);
      fs::create_dir_all(base.join("real")).unwrap();
      symlink(base.join("real"), base.join("link")).unwrap();
      assert!(SecureDirectory::open(&base.join("link")).is_err());
      fs::remove_dir_all(&base).unwrap();
    }
  }
}
