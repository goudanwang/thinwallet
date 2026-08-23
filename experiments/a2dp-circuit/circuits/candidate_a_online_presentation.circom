pragma circom 2.0.0;

include "components/age_predicate.circom";
include "components/request_binding.circom";
include "components/disclosure_control.circom";
include "components/credential_key_binding.circom";

template CandidateAOnlinePresentation() {
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

    signal input holder_public_key_x;
    signal input holder_public_key_y;
    signal input expected_enrollment_digest;

    signal input credential_commitment;
    signal input issuer_id;
    signal input schema_id;

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

    component binding = CredentialKeyBinding();
    binding.credential_commitment <== credential_commitment;
    binding.holder_public_key_x <== holder_public_key_x;
    binding.holder_public_key_y <== holder_public_key_y;
    binding.issuer_id <== issuer_id;
    binding.schema_id <== schema_id;
    binding.expected_enrollment_digest <== expected_enrollment_digest;
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
    holder_public_key_x,
    holder_public_key_y,
    expected_enrollment_digest
] } = CandidateAOnlinePresentation();
