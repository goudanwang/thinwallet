# ThinWallet Research Workspace

ThinWallet studies single-server assisted private SNARK proving for
resource-constrained mobile credential wallets.

Core implementation directories:

- `experiments/libspartan/`: the mobile-oriented Spartan prover, credential
  workloads, remote evaluation path, and native verifier integration;
- `experiments/preprocessed-pbmo/`: preprocessing, token lifecycle, transport,
  and malicious-response rejection for outsourced prover operations;
- `experiments/thinwallet-instrumentation/`: shared measurement support;
- `experiments/memory-bounded-sap/`: memory-bounded proving experiments;
- `experiments/a2dp-circuit/`: isolated Circom credential-circuit experiments;
- `experiments/frontier-tool/`: privacy-frontier analyzer, trace schemas,
  recorder mapping, Table 1 generator, and regression tests;
- `experiments/lightweight_tests/`: standalone verification and selected-path
  regression harnesses.

The project definition, protocol scope, security model, and artifact guidance
are under `docs/`. Generated build products, private inputs, proof bytes,
device-local state, and raw benchmark campaigns are intentionally excluded
from version control.
