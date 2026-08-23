pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";

template AgePredicate() {
    signal input birth_day_index;
    signal input cutoff_day_index;
    signal output is_old_enough;

    component birth_bits = Num2Bits(32);
    component cutoff_bits = Num2Bits(32);
    component is_lte = LessEqThan(32);

    birth_bits.in <== birth_day_index;
    cutoff_bits.in <== cutoff_day_index;

    is_lte.in[0] <== birth_day_index;
    is_lte.in[1] <== cutoff_day_index;

    is_old_enough <== is_lte.out;
    is_old_enough === 1;
}
