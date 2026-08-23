pragma circom 2.0.0;

include "components/age_predicate.circom";
include "components/request_binding.circom";
include "components/disclosure_control.circom";
include "components/holder_authorization.circom";

template OnlinePresentation() {
    signal input birth_day_index;
    signal input cutoff_day_index;

    signal input verifier_domain_hash;
    signal input nonce;
    signal input policy_hash;
    signal input requested_disclosure_mask;
    signal input expiry;
    signal input context_hash;
    signal input request_digest;

    signal input holder_approved_mask;
    signal input actual_disclosure_mask;
    signal input selection_commitment;
    signal input protocol_context;

    signal input holder_public_key_x;
    signal input holder_public_key_y;
    signal input signature_R8x;
    signal input signature_R8y;
    signal input signature_S;

    component age = AgePredicate();
    age.birth_day_index <== birth_day_index;
    age.cutoff_day_index <== cutoff_day_index;

    component request = RequestBinding();
    request.verifier_domain_hash <== verifier_domain_hash;
    request.nonce <== nonce;
    request.policy_hash <== policy_hash;
    request.requested_disclosure_mask <== requested_disclosure_mask;
    request.expiry <== expiry;
    request.context_hash <== context_hash;
    request.expected_request_digest <== request_digest;

    component disclosure = DisclosureControl();
    disclosure.requested_disclosure_mask <== requested_disclosure_mask;
    disclosure.holder_approved_mask <== holder_approved_mask;
    disclosure.actual_disclosure_mask <== actual_disclosure_mask;

    component authorization = HolderAuthorization();
    authorization.request_digest <== request_digest;
    authorization.holder_approved_mask <== holder_approved_mask;
    authorization.selection_commitment <== selection_commitment;
    authorization.protocol_context <== protocol_context;
    authorization.holder_public_key_x <== holder_public_key_x;
    authorization.holder_public_key_y <== holder_public_key_y;
    authorization.signature_R8x <== signature_R8x;
    authorization.signature_R8y <== signature_R8y;
    authorization.signature_S <== signature_S;
}

component main { public [
    cutoff_day_index,
    verifier_domain_hash,
    nonce,
    policy_hash,
    requested_disclosure_mask,
    expiry,
    context_hash,
    request_digest,
    holder_approved_mask,
    actual_disclosure_mask,
    selection_commitment,
    protocol_context
] } = OnlinePresentation();
