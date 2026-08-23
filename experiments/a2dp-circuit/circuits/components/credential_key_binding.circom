pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template CredentialKeyBinding() {
    signal input credential_commitment;
    signal input holder_public_key_x;
    signal input holder_public_key_y;
    signal input issuer_id;
    signal input schema_id;
    signal input expected_enrollment_digest;

    component enrollment_hash = Poseidon(5);

    enrollment_hash.inputs[0] <== credential_commitment;
    enrollment_hash.inputs[1] <== holder_public_key_x;
    enrollment_hash.inputs[2] <== holder_public_key_y;
    enrollment_hash.inputs[3] <== issuer_id;
    enrollment_hash.inputs[4] <== schema_id;

    enrollment_hash.out === expected_enrollment_digest;
}
