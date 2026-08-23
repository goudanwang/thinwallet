//! Allocation-level tracing used by the Phase V3A memory experiment.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Static attribution attached to allocations made inside a scope.
#[derive(Clone, Copy, Debug)]
pub struct AllocationClass {
  /// Source file containing the allocation site.
  pub source_file: &'static str,
  /// Function containing the allocation site.
  pub function: &'static str,
  /// Logical memory component.
  pub component: &'static str,
  /// Expected element type.
  pub element_type: &'static str,
  /// Whether the allocation contains private, public, or mixed data.
  pub privacy: &'static str,
  /// Whether the value can be deterministically regenerated.
  pub replayable: bool,
  /// Whether the value is a candidate for bounded streaming.
  pub streamable: bool,
}

const UNKNOWN_CLASS: AllocationClass = AllocationClass {
  source_file: "unknown",
  function: "unknown",
  component: "runtime/allocator overhead",
  element_type: "unknown",
  privacy: "unknown",
  replayable: false,
  streamable: false,
};

thread_local! {
  static CURRENT_CLASS: Cell<&'static AllocationClass> = const { Cell::new(&UNKNOWN_CLASS) };
  static IN_TRACER: Cell<bool> = const { Cell::new(false) };
}

/// Restores the previous allocation class when a logical scope exits.
pub struct AllocationScope {
  previous: &'static AllocationClass,
}

impl Drop for AllocationScope {
  fn drop(&mut self) {
    CURRENT_CLASS.with(|current| current.set(self.previous));
  }
}

/// Attributes allocations on the current thread until the returned guard drops.
pub fn scope(class: &'static AllocationClass) -> AllocationScope {
  let previous = CURRENT_CLASS.with(|current| {
    let previous = current.get();
    current.set(class);
    previous
  });
  AllocationScope { previous }
}

#[derive(Clone, Debug)]
struct LiveAllocation {
  id: u64,
  pointer: usize,
  requested_bytes: usize,
  created_ns: u128,
  class: &'static AllocationClass,
  live_bytes_at_creation: usize,
}

#[derive(Debug)]
struct Tracker {
  next_id: u64,
  live: Vec<LiveAllocation>,
  live_bytes: usize,
  peak_live_bytes: usize,
}

impl Default for Tracker {
  fn default() -> Self {
    Self {
      next_id: 1,
      live: Vec::new(),
      live_bytes: 0,
      peak_live_bytes: 0,
    }
  }
}

static TRACKER: OnceLock<Mutex<Tracker>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
static TRACE_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_THRESHOLD: AtomicUsize = AtomicUsize::new(64 * 1024);

fn enabled() -> bool {
  TRACE_ENABLED.load(Ordering::Relaxed)
}

fn threshold() -> usize {
  TRACE_THRESHOLD.load(Ordering::Relaxed)
}

fn elapsed_ns() -> u128 {
  START.get_or_init(Instant::now).elapsed().as_nanos()
}

fn rss_values() -> (Option<u64>, Option<u64>) {
  let Ok(status) = fs::read_to_string("/proc/self/status") else {
    return (None, None);
  };
  let mut rss = None;
  let mut hwm = None;
  for line in status.lines() {
    if line.starts_with("VmRSS:") {
      rss = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
    } else if line.starts_with("VmHWM:") {
      hwm = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
    }
  }
  (rss, hwm)
}

fn append_line(line: &str) {
  let Some(path) = TRACE_PATH.get() else {
    return;
  };
  if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
    let _ = file.write_all(line.as_bytes());
    let _ = file.write_all(b"\n");
    let _ = file.flush();
  }
}

fn with_tracer(f: impl FnOnce()) {
  IN_TRACER.with(|flag| {
    if flag.replace(true) {
      return;
    }
    f();
    flag.set(false);
  });
}

fn class_json(class: &AllocationClass) -> String {
  format!(
    "\"source_file\":\"{}\",\"function\":\"{}\",\"logical_component\":\"{}\",\"element_type\":\"{}\",\"privacy\":\"{}\",\"replayable\":{},\"streamable\":{}",
    class.source_file,
    class.function,
    class.component,
    class.element_type,
    class.privacy,
    class.replayable,
    class.streamable
  )
}

fn option_u64_json(value: Option<u64>) -> String {
  value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn record_alloc(pointer: *mut u8, layout: Layout, class: &'static AllocationClass) {
  if !enabled() || layout.size() < threshold() {
    return;
  }
  with_tracer(|| {
    let mut tracker = TRACKER.get_or_init(Default::default).lock().unwrap();
    let id = tracker.next_id;
    tracker.next_id += 1;
    tracker.live_bytes = tracker.live_bytes.saturating_add(layout.size());
    tracker.peak_live_bytes = tracker.peak_live_bytes.max(tracker.live_bytes);
    let created_ns = elapsed_ns();
    let live_bytes = tracker.live_bytes;
    let peak_live_bytes = tracker.peak_live_bytes;
    tracker.live.push(LiveAllocation {
      id,
      pointer: pointer as usize,
      requested_bytes: layout.size(),
      created_ns,
      class,
      live_bytes_at_creation: live_bytes,
    });
    let (rss, hwm) = rss_values();
    append_line(&format!(
      "{{\"event\":\"allocation_created\",\"allocation_id\":{id},\"timestamp_ns\":{created_ns},\"element_count\":null,\"requested_bytes\":{},\"actual_capacity_bytes\":{},\"logical_live_bytes\":{live_bytes},\"peak_logical_live_bytes\":{peak_live_bytes},\"rss_kib\":{},\"vmhwm_kib\":{},{}}}",
      layout.size(),
      layout.size(),
      option_u64_json(rss),
      option_u64_json(hwm),
      class_json(class)
    ));
  });
}

fn record_dealloc(pointer: *mut u8) {
  if !enabled() {
    return;
  }
  with_tracer(|| {
    let mut tracker = TRACKER.get_or_init(Default::default).lock().unwrap();
    let Some(index) = tracker
      .live
      .iter()
      .position(|item| item.pointer == pointer as usize)
    else {
      return;
    };
    let item = tracker.live.swap_remove(index);
    tracker.live_bytes = tracker.live_bytes.saturating_sub(item.requested_bytes);
    let destroyed_ns = elapsed_ns();
    append_line(&format!(
      "{{\"event\":\"allocation_destroyed\",\"allocation_id\":{},\"timestamp_ns\":{destroyed_ns},\"creation_time_ns\":{},\"destruction_time_ns\":{destroyed_ns},\"lifetime_ns\":{},\"requested_bytes\":{},\"actual_capacity_bytes\":{},\"logical_live_bytes\":{},\"peak_concurrent_lifetime_bytes\":{},{}}}",
      item.id,
      item.created_ns,
      destroyed_ns.saturating_sub(item.created_ns),
      item.requested_bytes,
      item.requested_bytes,
      tracker.live_bytes,
      item.live_bytes_at_creation,
      class_json(item.class)
    ));
  });
}

fn record_failure(layout: Layout, class: &'static AllocationClass) {
  if !enabled() {
    return;
  }
  with_tracer(|| {
    let tracker = TRACKER.get_or_init(Default::default).lock().unwrap();
    let mut largest = tracker.live.clone();
    largest.sort_by_key(|item| std::cmp::Reverse(item.requested_bytes));
    let top = largest
      .iter()
      .take(5)
      .map(|item| {
        format!(
          "{{\"allocation_id\":{},\"bytes\":{},\"component\":\"{}\",\"source_file\":\"{}\",\"function\":\"{}\"}}",
          item.id,
          item.requested_bytes,
          item.class.component,
          item.class.source_file,
          item.class.function
        )
      })
      .collect::<Vec<_>>()
      .join(",");
    let (rss, hwm) = rss_values();
    append_line(&format!(
      "{{\"event\":\"allocation_failed\",\"timestamp_ns\":{},\"requested_bytes\":{},\"actual_capacity_bytes\":null,\"logical_live_bytes\":{},\"peak_logical_live_bytes\":{},\"rss_kib\":{},\"vmhwm_kib\":{},\"failure_kind\":\"allocator_rejection\",\"largest_five_live_allocations\":[{}],{}}}",
      elapsed_ns(),
      layout.size(),
      tracker.live_bytes,
      tracker.peak_live_bytes,
      option_u64_json(rss),
      option_u64_json(hwm),
      top,
      class_json(class)
    ));
  });
}

/// Global allocator wrapper that records significant allocations and failures.
pub struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    let class = CURRENT_CLASS.with(Cell::get);
    let pointer = unsafe { System.alloc(layout) };
    if pointer.is_null() {
      record_failure(layout, class);
    } else {
      record_alloc(pointer, layout, class);
    }
    pointer
  }

  unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
    record_dealloc(pointer);
    unsafe { System.dealloc(pointer, layout) };
  }

  unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let class = CURRENT_CLASS.with(Cell::get);
    let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
    if new_pointer.is_null() {
      if let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) {
        record_failure(new_layout, class);
      }
    } else {
      record_dealloc(pointer);
      if let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) {
        record_alloc(new_pointer, new_layout, class);
      }
    }
    new_pointer
  }
}

/// Starts a fresh JSONL trace and records process metadata.
pub fn initialize_trace() {
  let Some(path) = std::env::var_os("V3A_MEMORY_TRACE_PATH") else {
    return;
  };
  let configured_threshold = std::env::var("V3A_MEMORY_TRACE_MIN_BYTES")
    .ok()
    .and_then(|value| value.parse().ok())
    .unwrap_or(64 * 1024);
  let _ = TRACE_PATH.set(path.into());
  TRACE_THRESHOLD.store(configured_threshold, Ordering::Relaxed);
  if let Some(path) = TRACE_PATH.get() {
    let _ = fs::remove_file(path);
  }
  TRACE_ENABLED.store(true, Ordering::Release);
  with_tracer(|| {
    let epoch_ms = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|value| value.as_millis())
      .unwrap_or_default();
    append_line(&format!(
      "{{\"event\":\"trace_started\",\"epoch_ms\":{epoch_ms},\"minimum_tracked_bytes\":{}}}",
      threshold()
    ));
  });
}

/// Persists a phase checkpoint with current RSS and the five largest live allocations.
pub fn snapshot(stage: &str) {
  if !enabled() {
    return;
  }
  with_tracer(|| {
    let tracker = TRACKER.get_or_init(Default::default).lock().unwrap();
    let (rss, hwm) = rss_values();
    append_line(&format!(
      "{{\"event\":\"snapshot\",\"stage\":\"{stage}\",\"timestamp_ns\":{},\"logical_live_bytes\":{},\"peak_logical_live_bytes\":{},\"rss_kib\":{},\"vmhwm_kib\":{}}}",
      elapsed_ns(),
      tracker.live_bytes,
      tracker.peak_live_bytes,
      option_u64_json(rss),
      option_u64_json(hwm)
    ));
  });
}
