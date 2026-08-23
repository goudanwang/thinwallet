# Phase 2B H Access Design

Phase 2B uses H0 as the primary h-access design:

- complete public h is installed into persistent client storage;
- h is authenticated by a manifest digest and modeled setup-authority signature;
- proving-time access uses local mmap/positional reads;
- the proving server does not receive h indices or h-read requests;
- only the sparse entries needed for `<e,h>` are read into temporary buffers.

The file format includes:

- magic value;
- backend ID;
- curve ID;
- n and N;
- parameter version;
- element byte length;
- root/body digest;
- endian and format version markers.

H0 reduces RAM, not persistent storage. The h vector remains public setup data
that must be installed and authenticated.

H2 private retrieval remains an open alternative. Phase 2B found no auditable
single-server PIR dependency integrated locally, so H2 implementation stops.

