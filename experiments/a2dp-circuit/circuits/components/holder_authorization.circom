pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template HolderAuthorization() {
    signal input request_digest;
    signal input holder_approved_mask;
    signal input selection_commitment;
    signal input protocol_context;

    signal input holder_public_key_x;
    signal input holder_public_key_y;
    signal input signature_R8x;
    signal input signature_R8y;
    signal input signature_S;

    component auth_hash = Poseidon(4);
    auth_hash.inputs[0] <== request_digest;
    auth_hash.inputs[1] <== holder_approved_mask;
    auth_hash.inputs[2] <== selection_commitment;
    auth_hash.inputs[3] <== protocol_context;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== holder_public_key_x;
    verifier.Ay <== holder_public_key_y;
    verifier.R8x <== signature_R8x;
    verifier.R8y <== signature_R8y;
    verifier.S <== signature_S;
    verifier.M <== auth_hash.out;
}
