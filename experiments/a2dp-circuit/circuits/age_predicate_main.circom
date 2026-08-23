pragma circom 2.0.0;

include "components/age_predicate.circom";

component main { public [cutoff_day_index] } = AgePredicate();
