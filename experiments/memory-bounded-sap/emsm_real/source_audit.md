# Source Audit

Repository audit found no complete paper-faithful EMSM / dual-LPN / RAA implementation that could be imported directly.

Found:

- Phase 1 adapter-only remote MSM: `experiments/memory-bounded-sap/remote_msm/remote_msm.py`

Not found:

- reusable EMSM Setup/Encrypt/Evaluate/Decrypt implementation;
- validated RAA parameter-generation code;
- production RAA encoder;
- private h retrieval implementation;
- EMSM serialization format from a reference implementation.

Phase 2A therefore implements the paper data flow locally for measurement and integration:

- RAA `G = F_r M_sigma1 A M_sigma2 A`;
- sparse noise `e` with nonconstant Hamming weight;
- streaming `v = z + G e`;
- server-side streaming evaluation;
- authenticated sparse h retrieval;
- decryption by `em - <e,h>`.

Classification: `PRODUCTION_UNVALIDATED`.
