pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/bitify.circom";

template DisclosureControl() {
    signal input requested_disclosure_mask;
    signal input holder_approved_mask;
    signal input actual_disclosure_mask;

    component requested_bits = Num2Bits(8);
    component approved_bits = Num2Bits(8);
    component actual_bits = Num2Bits(8);

    requested_bits.in <== requested_disclosure_mask;
    approved_bits.in <== holder_approved_mask;
    actual_bits.in <== actual_disclosure_mask;

    for (var i = 0; i < 8; i++) {
        approved_bits.out[i] * (1 - requested_bits.out[i]) === 0;
        actual_bits.out[i] === approved_bits.out[i];
    }
}
