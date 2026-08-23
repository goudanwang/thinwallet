# Phase V3B Budget-Aware Scheduler Plan

Phase V3B should turn the fixed FS2 choice into an explicit, deterministic
policy over measured memory budget, state size, storage capacity, and I/O
cost. It must never change transcript order, PBMO row order, blinding, proof
bytes, or verifier behavior.

The first milestone is replaying the Phase V3A cap matrix with a dry-run
planner that chooses in-memory or file-backed `comb_ops` before proving. A
second milestone may consider folded-table spilling only after allocation
lifetime and transcript-barrier tests match the V3A standard. Every decision
must be logged with its inputs and must fail closed when budget information is
missing or inconsistent.
