pragma circom 2.0.0;

include "components/disclosure_control.circom";

component main { public [
    requested_disclosure_mask,
    holder_approved_mask,
    actual_disclosure_mask
] } = DisclosureControl();
