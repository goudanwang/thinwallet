pragma circom 2.0.0;

include "components/holder_authorization.circom";

component main { public [
    request_digest,
    holder_approved_mask,
    selection_commitment,
    protocol_context
] } = HolderAuthorization();
