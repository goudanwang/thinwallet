//! Explicit prover budgets and accounting for Phase V3B modified paths.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Runtime memory and storage limits supplied by the caller.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ProverMemoryBudget {
  pub hard_limit_bytes: usize,
  pub reserved_runtime_bytes: usize,
  pub maximum_chunk_bytes: usize,
  pub maximum_inflight_network_bytes: usize,
  pub maximum_file_cache_bytes: usize,
  pub maximum_temporary_storage_bytes: u64,
}

impl ProverMemoryBudget {
  pub fn usable_prover_bytes(&self) -> io::Result<usize> {
    self
      .hard_limit_bytes
      .checked_sub(self.reserved_runtime_bytes)
      .ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::InvalidInput,
          "runtime reserve exceeds hard limit",
        )
      })
  }

  pub fn from_env() -> io::Result<Self> {
    fn value(name: &str, default: u64) -> io::Result<u64> {
      std::env::var(name)
        .ok()
        .map(|raw| {
          raw
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {name}")))
        })
        .transpose()
        .map(|parsed| parsed.unwrap_or(default))
    }
    let budget = Self {
      hard_limit_bytes: value("V3B_HARD_LIMIT_BYTES", 1024 * 1024 * 1024)? as usize,
      reserved_runtime_bytes: value("V3B_RESERVED_RUNTIME_BYTES", 64 * 1024 * 1024)? as usize,
      maximum_chunk_bytes: value("V3B_MAXIMUM_CHUNK_BYTES", 1024 * 1024)? as usize,
      maximum_inflight_network_bytes: value("V3B_MAXIMUM_INFLIGHT_NETWORK_BYTES", 8 * 1024 * 1024)?
        as usize,
      maximum_file_cache_bytes: value("V3B_MAXIMUM_FILE_CACHE_BYTES", 8 * 1024 * 1024)? as usize,
      maximum_temporary_storage_bytes: value(
        "V3B_MAXIMUM_TEMPORARY_STORAGE_BYTES",
        4 * 1024 * 1024 * 1024,
      )?,
    };
    if budget.maximum_chunk_bytes == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "zero chunk bound",
      ));
    }
    budget.usable_prover_bytes()?;
    Ok(budget)
  }
}

/// Capacity-based accounting for buffers introduced by the FS3 path.
#[derive(Clone, Debug)]
pub struct BudgetAccountedArena {
  usable_bytes: usize,
  current_bytes: Arc<AtomicUsize>,
  peak_bytes: Arc<AtomicUsize>,
}

impl BudgetAccountedArena {
  pub fn new(usable_bytes: usize) -> Self {
    Self {
      usable_bytes,
      current_bytes: Arc::new(AtomicUsize::new(0)),
      peak_bytes: Arc::new(AtomicUsize::new(0)),
    }
  }

  pub fn reserve(&self, capacity_bytes: usize) -> io::Result<BudgetReservation> {
    let mut current = self.current_bytes.load(Ordering::Acquire);
    loop {
      let next = current.checked_add(capacity_bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::OutOfMemory, "accounted allocation overflow")
      })?;
      if next > self.usable_bytes {
        return Err(io::Error::new(
          io::ErrorKind::OutOfMemory,
          format!(
            "controlled budget rejection: {next} > {}",
            self.usable_bytes
          ),
        ));
      }
      match self.current_bytes.compare_exchange_weak(
        current,
        next,
        Ordering::AcqRel,
        Ordering::Acquire,
      ) {
        Ok(_) => {
          self.peak_bytes.fetch_max(next, Ordering::AcqRel);
          return Ok(BudgetReservation {
            bytes: capacity_bytes,
            current_bytes: Arc::clone(&self.current_bytes),
          });
        }
        Err(observed) => current = observed,
      }
    }
  }

  pub fn current_bytes(&self) -> usize {
    self.current_bytes.load(Ordering::Acquire)
  }

  pub fn peak_bytes(&self) -> usize {
    self.peak_bytes.load(Ordering::Acquire)
  }
}

/// Releases an arena reservation at the selected object's last use.
pub struct BudgetReservation {
  bytes: usize,
  current_bytes: Arc<AtomicUsize>,
}

impl Drop for BudgetReservation {
  fn drop(&mut self) {
    self.current_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn arena_rejects_before_allocation_and_releases() {
    let arena = BudgetAccountedArena::new(16);
    let first = arena.reserve(12).unwrap();
    assert!(arena.reserve(8).is_err());
    assert_eq!(arena.current_bytes(), 12);
    drop(first);
    assert_eq!(arena.current_bytes(), 0);
    assert_eq!(arena.peak_bytes(), 12);
  }
}
