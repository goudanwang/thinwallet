# Phase V3A Rollback Profiles

Phase V3A uses `SoftwareCrashConsistentProvider`. Durable reservation and
one-time token consumption survive ordinary crashes, but an attacker able to
restore a complete earlier device snapshot can also restore token state.

Profile A is software-only and crash-safe. Whole-device snapshot rollback is
outside its threat model. Profile B includes strong rollback protection and
therefore requires hardware monotonic state or an independent external
witness. No trusted counter is simulated in software.

```text
SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED
STRONG_ROLLBACK_PROTECTION_REQUIRES_EXTERNAL_ASSUMPTION
THINWALLET_ROLLBACK_PROFILES_DOCUMENTED
```
