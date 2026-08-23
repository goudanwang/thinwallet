# Android Benchmark Checklist

- Confirm the V4F desktop release-candidate hashes before deployment.
- Obtain device-owner authorization and set `THINWALLET_ANDROID_AUTHORIZED=YES`.
- Record the complete required device profile and ARM64 binary SHA-256.
- Fix build profile, worker count, CPU policy, filesystem location, token policy, and network profile.
- Record battery, charging, airplane/Wi-Fi/cellular, thermal and CPU-frequency state before and after every run.
- Run correctness and unchanged-verifier smoke tests before performance cells.
- Measure cold and warm runs separately; preserve raw stdout, stderr and exit status.
- Record RSS, PSS, VmHWM, cgroup current/peak where available, swap/OOM, temporary storage, reads/writes and context switches.
- Measure local proving, PBMO transport, server MSM and complete presentation separately.
- Exercise crash before/after token reservation and aborted-proving cleanup without reusing a token.
- Use five repetitions for final boundaries and headline cells; do not discard outliers without a predefined rule.
- Pull all artifacts, verify hashes and archive failures without interpolation.
