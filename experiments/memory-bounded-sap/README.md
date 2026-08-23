# Memory-Bounded SAP Phase 1

Mainline: `MEMORY_BOUNDED_SUMCHECK_SERVER_AIDED_SNARK`.

Run:

```bash
bash run_phase1.sh
```

The Python entrypoint can be run alone with:

```bash
python3 run_phase1.py
```

Phase 1 implements an internal FFT-free multilinear Sumcheck backend for architecture validation. It is not a production SNARK and does not claim private outsourcing.

Core interfaces:

- `WitnessSource.next_chunk(B) -> FieldChunk`
- `FoldStore.read_chunk(offset, length) -> FieldChunk`
- `FoldStore.append_chunk(FieldChunk)`
- `FoldStore.finish_round()`
- `local_prove(statement, witness) -> proof`
- `native_verify(statement, proof) -> bool`
- `plaintext_remote_msm(scalars) -> result`
- `build_manifest(vector_length) -> ParameterManifest`

Expected Phase 1 status markers include:

- `SUMCHECK_MEMORY_BOUNDED_MAINLINE_INITIALIZED`
- `SUMCHECK_BACKEND_SELECTED`
- `CLIENT_PROVER_FFT_FREE_PASS`
- `NATIVE_SUMCHECK_BASELINE_PASS`
- `STREAMING_SUMCHECK_TRANSCRIPT_MATCH_PASS`
- `MEMORY_BOUNDED_SAP_NEGATIVE_TESTS_PASS`

Current classification: `MEMORY_BOUNDED_SAP_BLOCKED_BY_EMSM_STREAMING`.

