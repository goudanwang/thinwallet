# Resume Android V4A

Desktop Phase V4B is frozen before Android work resumes. Current blocker:
`NO_AUTHORIZED_PHYSICAL_ARM64_ANDROID_DEVICE`.

Resume only after `adb devices -l` shows an authorized physical ARM64 device.
Rebuild the frozen native revision, provision app-private token/state paths,
run W1-W4 E3/E4 without changing proof or verifier code, and record native RSS,
PSS, latency, energy, thermal state, network behavior, token lifecycle, and all
device/build identifiers. Emulator or desktop results must not be relabeled as
physical-device evidence.
