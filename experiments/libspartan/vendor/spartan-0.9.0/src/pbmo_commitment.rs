//! Prover-only complete fragmented-commitment PBMO adapter.
//!
//! The generic provider and protocol live in the separate `preprocessed-pbmo`
//! crate. This module only maps libspartan's ordered q-by-m witness matrix to
//! that API. Native row blinding remains in `dense_mlpoly`.

use crate::group::GroupElement;
use crate::scalar::{Scalar, ScalarBytes, ScalarBytesFromScalar};
use core::cell::RefCell;
use preprocessed_pbmo::{PbmoContext, PbmoMetrics, PreprocessedPbmoProvider};
use serde::{Deserialize, Serialize};

/// Configuration for one complete fragmented private commitment.
pub struct FullPbmoRunConfig {
  /// Bound streaming context.
  pub context: PbmoContext,
  /// Maximum scalar count in each row chunk.
  pub chunk_size: usize,
  /// Generic provider implementation.
  pub provider: Box<dyn PreprocessedPbmoProvider>,
}

/// Report produced before the native blind terms are added.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullPbmoRunReport {
  /// Whether the complete logical commitment was selected.
  pub selected: bool,
  /// Number of output rows.
  pub q: usize,
  /// Number of shared-basis scalars per row.
  pub m: usize,
  /// Actual provider metrics.
  pub metrics: Option<PbmoMetrics>,
  /// Ordered unblinded output encodings.
  pub output_points: Vec<[u8; 32]>,
}

struct ActiveRun {
  config: FullPbmoRunConfig,
  report: FullPbmoRunReport,
}

thread_local! {
  static ACTIVE_RUN: RefCell<Option<ActiveRun>> = const { RefCell::new(None) };
}

/// Execute one normal prover call with the complete private witness commitment
/// routed through a generic PBMO provider.
pub fn with_full_pbmo_provider<T>(
  config: FullPbmoRunConfig,
  f: impl FnOnce() -> T,
) -> (T, FullPbmoRunReport) {
  ACTIVE_RUN.with(|slot| {
    assert!(slot.borrow().is_none(), "nested full PBMO provider scopes");
    *slot.borrow_mut() = Some(ActiveRun {
      config,
      report: FullPbmoRunReport {
        selected: false,
        q: 0,
        m: 0,
        metrics: None,
        output_points: Vec::new(),
      },
    });
  });
  let output = f();
  let report = ACTIVE_RUN.with(|slot| slot.borrow_mut().take().unwrap().report);
  #[cfg(feature = "thinwallet-experiment")]
  if report.selected {
    thinwallet_instrumentation::record_trace_unit(
      "hyrax_row_msm",
      &["commit_inner_row_msm"],
      "Mask",
      "PBMO",
    );
  }
  (output, report)
}

/// Route all q rows through the active provider, if one is scoped.
pub(crate) fn maybe_commit_private_rows(
  scalars: &[Scalar],
  q: usize,
  m: usize,
  bases: &[GroupElement],
) -> Option<Vec<GroupElement>> {
  ACTIVE_RUN.with(|slot| {
    let mut slot = slot.borrow_mut();
    let active = slot.as_mut()?;
    assert!(!active.report.selected, "private commitment selected twice");
    assert_eq!(scalars.len(), q * m);
    assert_eq!(bases.len(), m);
    let chunk_size = active.config.chunk_size.max(1).min(m);
    let expected_chunks = q * m.div_ceil(chunk_size);
    assert_eq!(
      active.config.context.expected_chunks as usize, expected_chunks,
      "PBMO context chunk count mismatch"
    );
    let provider = active.config.provider.as_mut();
    let mut session = provider
      .begin(active.config.context.clone(), q, m)
      .expect("PBMO begin failed");
    for row in 0..q {
      for start in (0..m).step_by(chunk_size) {
        let end = (start + chunk_size).min(m);
        let converted: Vec<ScalarBytes> = scalars[row * m + start..row * m + end]
          .iter()
          .map(Scalar::decompress_scalar)
          .collect();
        provider
          .push_private_row_chunk(&mut session, row, start..end, &converted)
          .expect("PBMO row chunk failed");
      }
    }
    let points = provider.finalize(session).expect("PBMO finalize failed");
    assert_eq!(points.len(), q);
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_trace_event(
      "commit_inner_row_msm",
      &["poly_vars", "G"],
      &["row_points"],
      None,
      &[],
      false,
    );
    active.report = FullPbmoRunReport {
      selected: true,
      q,
      m,
      metrics: provider.last_metrics().cloned(),
      output_points: points
        .iter()
        .map(|point| point.compress().to_bytes())
        .collect(),
    };
    Some(points)
  })
}
