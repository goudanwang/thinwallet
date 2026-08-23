pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template RequestBinding() {
    signal input verifier_domain_hash;
    signal input nonce;
    signal input policy_hash;
    signal input requested_disclosure_mask;
    signal input expiry;
    signal input context_hash;
    signal input expected_request_digest;

    component request_hash = Poseidon(6);

    request_hash.inputs[0] <== verifier_domain_hash;
    request_hash.inputs[1] <== nonce;
    request_hash.inputs[2] <== policy_hash;
    request_hash.inputs[3] <== requested_disclosure_mask;
    request_hash.inputs[4] <== expiry;
    request_hash.inputs[5] <== context_hash;

    request_hash.out === expected_request_digest;
}
