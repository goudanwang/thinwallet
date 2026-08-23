pragma circom 2.0.0;

include "components/request_binding.circom";

component main { public [
    verifier_domain_hash,
    nonce,
    policy_hash,
    requested_disclosure_mask,
    expiry,
    context_hash,
    expected_request_digest
] } = RequestBinding();
