# Phase V4 Android Core Port Plan

Status: NOT STARTED. Phase V3B is a WSL memory result and is not evidence of Android feasibility.

The first Android task is to isolate the FS3 prover core behind an FFI-safe API, reproduce proof bytes against the frozen desktop fixture, and measure native allocator RSS on a real arm64 device. No Java/Kotlin layer should retain witness-sized buffers. The gate is byte-identical proof output accepted by the unchanged verifier under an explicitly enforced device memory budget.
