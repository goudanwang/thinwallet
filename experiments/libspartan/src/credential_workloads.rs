#![allow(dead_code)]
#![allow(clippy::implicit_saturating_sub, clippy::too_many_arguments)]

use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use sha3::{Digest, Sha3_512};
use std::collections::BTreeMap;
use std::time::Instant;

#[path = "credential_workloads/profile_s.rs"]
pub mod profile_s;

pub type MatrixEntry = (usize, usize, [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workload {
    W0,
    W1,
    W2,
    W3,
    W4,
}

impl Workload {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "W0" => Some(Self::W0),
            "W1" => Some(Self::W1),
            "W2" => Some(Self::W2),
            "W3" => Some(Self::W3),
            "W4" => Some(Self::W4),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::W0 => "synthetic_regression",
            Self::W1 => "single_credential",
            Self::W2 => "predicate_credential",
            Self::W3 => "revocable_credential",
            Self::W4 => "multi_credential",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Mutation {
    Valid,
    Boundary,
    Attribute,
    Issuer,
    Holder,
    Mac,
    Nonce,
    Expired,
    Revoked,
    StaleRoot,
    MerklePath,
    CrossCredential,
}

#[derive(Clone, Serialize)]
pub struct WorkloadMetadata {
    pub workload: String,
    pub relation: String,
    pub raw_constraints: usize,
    pub raw_variables: usize,
    pub witness_elements: usize,
    pub public_inputs: usize,
    pub padded_size: usize,
    pub q: usize,
    pub m: usize,
    pub fragmented_outputs: usize,
    pub padding_constraints: usize,
    pub padding_variables: usize,
    pub constraint_composition: BTreeMap<String, usize>,
    pub construction_ms: f64,
    pub witness_generation_ms: f64,
    pub revocation_depth: Option<usize>,
    pub revocation_path_length: Option<usize>,
    pub revocation_count: usize,
    pub revocation_backend: String,
    pub issuer_authentication: &'static str,
    pub issuer_authentication_assumption: &'static str,
}

pub struct RelationFixture {
    pub a: Vec<MatrixEntry>,
    pub b: Vec<MatrixEntry>,
    pub c: Vec<MatrixEntry>,
    pub vars: Vec<[u8; 32]>,
    pub inputs: Vec<[u8; 32]>,
    pub metadata: WorkloadMetadata,
}

#[derive(Clone, Copy)]
enum Wire {
    Var(usize),
    Input(usize),
    One,
}

#[derive(Clone)]
struct Lc(Vec<(Wire, Scalar)>);

impl Lc {
    fn var(index: usize) -> Self {
        Self(vec![(Wire::Var(index), Scalar::ONE)])
    }

    fn input(index: usize) -> Self {
        Self(vec![(Wire::Input(index), Scalar::ONE)])
    }

    fn one() -> Self {
        Self(vec![(Wire::One, Scalar::ONE)])
    }

    fn constant(value: Scalar) -> Self {
        Self(vec![(Wire::One, value)])
    }

    fn add_term(mut self, wire: Wire, coefficient: Scalar) -> Self {
        self.0.push((wire, coefficient));
        self
    }

    fn add_constant(self, value: Scalar) -> Self {
        self.add_term(Wire::One, value)
    }
}

struct Builder {
    vars: Vec<Scalar>,
    inputs: Vec<Scalar>,
    rows: Vec<(Lc, Lc, Lc)>,
    composition: BTreeMap<String, usize>,
}

impl Builder {
    fn new() -> Self {
        Self {
            vars: Vec::new(),
            inputs: Vec::new(),
            rows: Vec::new(),
            composition: BTreeMap::new(),
        }
    }

    fn alloc(&mut self, value: Scalar) -> usize {
        let index = self.vars.len();
        self.vars.push(value);
        index
    }

    fn public(&mut self, value: Scalar) -> usize {
        let index = self.inputs.len();
        self.inputs.push(value);
        index
    }

    fn enforce(&mut self, category: &str, a: Lc, b: Lc, c: Lc) {
        self.rows.push((a, b, c));
        *self.composition.entry(category.to_owned()).or_default() += 1;
    }

    fn enforce_equal(&mut self, category: &str, left: Lc, right: Lc) {
        let mut difference = left;
        for (wire, coefficient) in right.0 {
            difference.0.push((wire, -coefficient));
        }
        self.enforce(category, difference, Lc::one(), Lc::constant(Scalar::ZERO));
    }

    fn mul(&mut self, category: &str, left: Lc, right: Lc, value: Scalar) -> usize {
        let output = self.alloc(value);
        self.enforce(category, left, right, Lc::var(output));
        output
    }

    fn bit(&mut self, category: &str, value: bool) -> usize {
        let scalar = Scalar::from(value as u64);
        let bit = self.alloc(scalar);
        let one_minus = Lc::constant(Scalar::ONE).add_term(Wire::Var(bit), -Scalar::ONE);
        self.enforce(
            category,
            Lc::var(bit),
            one_minus,
            Lc::constant(Scalar::ZERO),
        );
        bit
    }

    fn decompose_u32(&mut self, category: &str, value: u64, source: Lc) -> Vec<usize> {
        let bits: Vec<_> = (0..32)
            .map(|i| self.bit(category, ((value >> i) & 1) == 1))
            .collect();
        let mut packed = Lc::constant(Scalar::ZERO);
        let mut coefficient = Scalar::ONE;
        for bit in &bits {
            packed = packed.add_term(Wire::Var(*bit), coefficient);
            coefficient += coefficient;
        }
        self.enforce_equal(category, packed, source);
        bits
    }

    fn less_equal_u32(
        &mut self,
        category: &str,
        left_value: u64,
        left: Lc,
        right_value: u64,
        right: Lc,
    ) {
        self.decompose_u32(category, left_value, left.clone());
        self.decompose_u32(category, right_value, right.clone());
        let difference = if right_value >= left_value {
            right_value - left_value
        } else {
            0
        };
        let difference_var = self.alloc(Scalar::from(difference));
        self.decompose_u32(category, difference, Lc::var(difference_var));
        let expected = right.add_term(Wire::Var(difference_var), -Scalar::ONE);
        self.enforce_equal(category, left, expected);
    }
}

fn round_constant(round: usize) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"thinwallet-v4b-mimc7-ristretto255-v1");
    hasher.update((round as u64).to_le_bytes());
    let bytes: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn native_permute(mut state: Scalar, key: Scalar) -> Scalar {
    for round in 0..91 {
        let x = state + key + round_constant(round);
        let x2 = x * x;
        let x4 = x2 * x2;
        state = x4 * x2 * x;
    }
    state + key
}

fn native_hash(blocks: &[Scalar], key: Scalar, domain: u64) -> Scalar {
    let mut state = Scalar::from(domain);
    for block in blocks {
        state = native_permute(state + block, key);
    }
    state
}

fn circuit_permute(
    builder: &mut Builder,
    mut state: Lc,
    state_value: Scalar,
    key: Lc,
    key_value: Scalar,
    category: &str,
) -> (Lc, Scalar) {
    let mut value = state_value;
    for round in 0..91 {
        let constant = round_constant(round);
        let x_value = value + key_value + constant;
        let x = state.clone().add_constant(constant);
        let mut x_with_key = x;
        x_with_key.0.extend(key.0.iter().copied());
        let x2 = builder.mul(
            category,
            x_with_key.clone(),
            x_with_key.clone(),
            x_value * x_value,
        );
        let x4_value = x_value * x_value * x_value * x_value;
        let x4 = builder.mul(category, Lc::var(x2), Lc::var(x2), x4_value);
        let x6 = builder.mul(
            category,
            Lc::var(x4),
            Lc::var(x2),
            x4_value * x_value * x_value,
        );
        let x7_value = x4_value * x_value * x_value * x_value;
        let x7 = builder.mul(category, Lc::var(x6), x_with_key, x7_value);
        state = Lc::var(x7);
        value = x7_value;
    }
    let output_value = value + key_value;
    let output = builder.alloc(output_value);
    let mut expected = state;
    expected.0.extend(key.0);
    builder.enforce_equal(category, Lc::var(output), expected);
    (Lc::var(output), output_value)
}

fn circuit_hash(
    builder: &mut Builder,
    blocks: &[(Lc, Scalar)],
    key: (Lc, Scalar),
    domain: u64,
    category: &str,
) -> (Lc, Scalar) {
    let mut state = Lc::constant(Scalar::from(domain));
    let mut state_value = Scalar::from(domain);
    for (block, block_value) in blocks {
        state.0.extend(block.0.iter().copied());
        state_value += block_value;
        (state, state_value) =
            circuit_permute(builder, state, state_value, key.0.clone(), key.1, category);
    }
    (state, state_value)
}

#[derive(Clone)]
struct Credential {
    issuer_key: u64,
    issuer_id: u64,
    schema_id: u64,
    credential_id: u64,
    holder_secret: u64,
    age: u64,
    country: u64,
    expiry: u64,
    revocation_index: u64,
}

impl Credential {
    fn holder_commitment(&self) -> Scalar {
        native_hash(
            &[Scalar::from(self.holder_secret)],
            Scalar::ZERO,
            0x484f4c44,
        )
    }

    fn key_commitment(&self) -> Scalar {
        native_hash(
            &[Scalar::from(self.issuer_key), Scalar::from(self.issuer_id)],
            Scalar::ZERO,
            0x49534b43,
        )
    }

    fn mac(&self) -> Scalar {
        native_hash(
            &[
                Scalar::from(self.issuer_id),
                Scalar::from(self.schema_id),
                Scalar::from(self.credential_id),
                self.holder_commitment(),
                Scalar::from(self.age),
                Scalar::from(self.country),
                Scalar::from(self.expiry),
                Scalar::from(self.revocation_index),
            ],
            Scalar::from(self.issuer_key),
            0x43524544,
        )
    }
}

fn default_credential(second: bool) -> Credential {
    Credential {
        issuer_key: if second { 0x2a02 } else { 0x2a01 },
        issuer_id: if second { 202 } else { 101 },
        schema_id: if second { 12 } else { 11 },
        credential_id: if second { 0x2005 } else { 0x1005 },
        holder_secret: 0x5151,
        age: 24,
        country: 36,
        expiry: 25_000,
        revocation_index: 5,
    }
}

fn merkle_path(depth: usize) -> Vec<Scalar> {
    (0..depth)
        .map(|i| native_hash(&[Scalar::from(0x9000 + i as u64)], Scalar::ZERO, 0x5349424c))
        .collect()
}

fn merkle_root(index: u64, path: &[Scalar], leaf: Scalar) -> Scalar {
    let mut current = leaf;
    for (level, sibling) in path.iter().enumerate() {
        let bit = (index >> level) & 1;
        let pair = if bit == 0 {
            [current, *sibling]
        } else {
            [*sibling, current]
        };
        current = native_hash(&pair, Scalar::ZERO, 0x4d45524b);
    }
    current
}

fn add_credential(
    builder: &mut Builder,
    credential: &Credential,
    expected_mac: Scalar,
    label: &str,
) -> (usize, usize, usize, usize, usize) {
    let key = builder.alloc(Scalar::from(credential.issuer_key));
    let holder_secret = builder.alloc(Scalar::from(credential.holder_secret));
    let age = builder.alloc(Scalar::from(credential.age));
    let country = builder.alloc(Scalar::from(credential.country));
    let expiry = builder.alloc(Scalar::from(credential.expiry));
    let revocation_index = builder.alloc(Scalar::from(credential.revocation_index));
    let issuer = builder.public(Scalar::from(credential.issuer_id));
    let key_commitment = builder.public(credential.key_commitment());

    let (holder_commitment, holder_value) = circuit_hash(
        builder,
        &[(
            Lc::var(holder_secret),
            Scalar::from(credential.holder_secret),
        )],
        (Lc::constant(Scalar::ZERO), Scalar::ZERO),
        0x484f4c44,
        "holder_binding_hash",
    );
    let (computed_key_commitment, _) = circuit_hash(
        builder,
        &[
            (Lc::var(key), Scalar::from(credential.issuer_key)),
            (Lc::input(issuer), Scalar::from(credential.issuer_id)),
        ],
        (Lc::constant(Scalar::ZERO), Scalar::ZERO),
        0x49534b43,
        "issuer_key_commitment",
    );
    builder.enforce_equal(
        "issuer_key_commitment",
        computed_key_commitment,
        Lc::input(key_commitment),
    );

    let blocks = vec![
        (Lc::input(issuer), Scalar::from(credential.issuer_id)),
        (
            Lc::constant(Scalar::from(credential.schema_id)),
            Scalar::from(credential.schema_id),
        ),
        (
            Lc::constant(Scalar::from(credential.credential_id)),
            Scalar::from(credential.credential_id),
        ),
        (holder_commitment, holder_value),
        (Lc::var(age), Scalar::from(credential.age)),
        (Lc::var(country), Scalar::from(credential.country)),
        (Lc::var(expiry), Scalar::from(credential.expiry)),
        (
            Lc::var(revocation_index),
            Scalar::from(credential.revocation_index),
        ),
    ];
    let (computed_mac, _) = circuit_hash(
        builder,
        &blocks,
        (Lc::var(key), Scalar::from(credential.issuer_key)),
        0x43524544,
        "issuer_mimc7_prf_mac",
    );
    let supplied_mac = builder.alloc(expected_mac);
    builder.enforce_equal(
        &format!("issuer_mac_equality_{label}"),
        computed_mac,
        Lc::var(supplied_mac),
    );
    (holder_secret, age, country, expiry, revocation_index)
}

fn add_request_binding(
    builder: &mut Builder,
    holder_secret: usize,
    holder_value: u64,
    nonce_value: u64,
    mask_value: u64,
    expected_digest: Scalar,
) -> (usize, usize) {
    let nonce = builder.public(Scalar::from(nonce_value));
    let mask = builder.public(Scalar::from(mask_value));
    let digest = builder.public(expected_digest);
    let (computed, _) = circuit_hash(
        builder,
        &[
            (Lc::var(holder_secret), Scalar::from(holder_value)),
            (Lc::input(nonce), Scalar::from(nonce_value)),
            (Lc::input(mask), Scalar::from(mask_value)),
        ],
        (Lc::constant(Scalar::ZERO), Scalar::ZERO),
        0x52455155,
        "nonce_session_binding",
    );
    builder.enforce_equal("nonce_session_binding", computed, Lc::input(digest));
    (mask, nonce)
}

fn add_disclosure(
    builder: &mut Builder,
    age: usize,
    age_value: u64,
    country: usize,
    country_value: u64,
    mask_input: usize,
    mask_value: u64,
) {
    let mask_bits =
        builder.decompose_u32("disclosure_mask_range", mask_value, Lc::input(mask_input));
    for bit in mask_bits.iter().skip(2) {
        builder.enforce_equal(
            "disclosure_mask_range",
            Lc::var(*bit),
            Lc::constant(Scalar::ZERO),
        );
    }
    let disclosed_age = builder.public(Scalar::from(if mask_value & 1 == 1 {
        age_value
    } else {
        0
    }));
    let disclosed_country = builder.public(Scalar::from(if mask_value & 2 == 2 {
        country_value
    } else {
        0
    }));
    let age_difference = Lc::var(age).add_term(Wire::Input(disclosed_age), -Scalar::ONE);
    let country_difference =
        Lc::var(country).add_term(Wire::Input(disclosed_country), -Scalar::ONE);
    builder.enforce(
        "selective_disclosure",
        Lc::var(mask_bits[0]),
        age_difference,
        Lc::constant(Scalar::ZERO),
    );
    builder.enforce(
        "selective_disclosure",
        Lc::var(mask_bits[1]),
        country_difference,
        Lc::constant(Scalar::ZERO),
    );
}

fn add_range_and_expiry(
    builder: &mut Builder,
    age: usize,
    age_value: u64,
    expiry: usize,
    expiry_value: u64,
    current_day: u64,
) {
    let min_age_value = 18;
    let max_age_value = 65;
    let min_age = builder.public(Scalar::from(min_age_value));
    let max_age = builder.public(Scalar::from(max_age_value));
    let now = builder.public(Scalar::from(current_day));
    builder.less_equal_u32(
        "numeric_range",
        min_age_value,
        Lc::input(min_age),
        age_value,
        Lc::var(age),
    );
    builder.less_equal_u32(
        "numeric_range",
        age_value,
        Lc::var(age),
        max_age_value,
        Lc::input(max_age),
    );
    builder.less_equal_u32(
        "expiry",
        current_day,
        Lc::input(now),
        expiry_value,
        Lc::var(expiry),
    );
}

fn add_revocation(
    builder: &mut Builder,
    index: usize,
    index_value: u64,
    root: Scalar,
    path: &[Scalar],
    root_epoch: u64,
    request_epoch: u64,
    corrupted_path: bool,
    revoked: bool,
) {
    let root_input = builder.public(root);
    let root_epoch_input = builder.public(Scalar::from(root_epoch));
    let request_epoch_input = builder.public(Scalar::from(request_epoch));
    builder.enforce_equal(
        "revocation_root_freshness",
        Lc::input(root_epoch_input),
        Lc::input(request_epoch_input),
    );
    let bits = builder.decompose_u32("revocation_index", index_value, Lc::var(index));
    for bit in bits.iter().skip(path.len()) {
        builder.enforce_equal(
            "revocation_index",
            Lc::var(*bit),
            Lc::constant(Scalar::ZERO),
        );
    }
    let mut current = Lc::constant(Scalar::from(revoked as u64));
    let mut current_value = Scalar::from(revoked as u64);
    for (level, original_sibling) in path.iter().enumerate() {
        let sibling_value = if corrupted_path && level == 0 {
            *original_sibling + Scalar::ONE
        } else {
            *original_sibling
        };
        let sibling = builder.alloc(sibling_value);
        let bit_value = ((index_value >> level) & 1) == 1;
        let delta_value = sibling_value - current_value;
        let selected_value = if bit_value { delta_value } else { Scalar::ZERO };
        let selected = builder.mul(
            "revocation_path_selection",
            Lc::var(bits[level]),
            Lc::var(sibling).add_term(
                match &current.0[0].0 {
                    Wire::Var(v) => Wire::Var(*v),
                    _ => Wire::One,
                },
                Scalar::ZERO,
            ),
            selected_value,
        );
        // Replace the generic right operand above with sibling-current while retaining one multiplication.
        let row = builder.rows.last_mut().expect("selection row");
        row.1 = Lc::var(sibling);
        for (wire, coefficient) in current.0.iter().copied() {
            row.1 .0.push((wire, -coefficient));
        }
        let left = {
            let mut lc = current.clone();
            lc.0.push((Wire::Var(selected), Scalar::ONE));
            lc
        };
        let right = Lc::var(sibling).add_term(Wire::Var(selected), -Scalar::ONE);
        let ordered_left = left;
        let ordered_right = right;
        let ordered_left_value = current_value + selected_value;
        let ordered_right_value = sibling_value - selected_value;
        let (next, next_value) = circuit_hash(
            builder,
            &[
                (ordered_left, ordered_left_value),
                (ordered_right, ordered_right_value),
            ],
            (Lc::constant(Scalar::ZERO), Scalar::ZERO),
            0x4d45524b,
            "revocation_merkle_hash",
        );
        current = next;
        current_value = next_value;
    }
    builder.enforce_equal("revocation_root", current, Lc::input(root_input));
}

fn build_non_synthetic(workload: Workload, mutation: Mutation) -> (Builder, Option<usize>) {
    let mut builder = Builder::new();
    let mut first = default_credential(false);
    let mut second = default_credential(true);
    if matches!(mutation, Mutation::Boundary) {
        first.age = 18;
        if workload == Workload::W4 {
            second.age = 18;
        }
    }
    let valid_first = first.clone();
    let valid_second = second.clone();
    let mut nonce = 0x7777;
    let mut current_day = 24_000;
    match mutation {
        Mutation::Attribute => first.age += 1,
        Mutation::Issuer => first.issuer_id += 1,
        Mutation::Holder => first.holder_secret += 1,
        Mutation::Nonce => nonce += 1,
        Mutation::Expired => current_day = 26_000,
        Mutation::CrossCredential => second.holder_secret += 1,
        _ => {}
    }
    let first_mac = if matches!(mutation, Mutation::Mac) {
        valid_first.mac() + Scalar::ONE
    } else {
        valid_first.mac()
    };
    let (holder, age, country, expiry, revocation_index) =
        add_credential(&mut builder, &first, first_mac, "first");
    let mask_value = match workload {
        Workload::W1 => 1,
        Workload::W2 | Workload::W3 => 2,
        Workload::W4 => 0,
        Workload::W0 => unreachable!(),
    };
    let valid_request_digest = native_hash(
        &[
            Scalar::from(valid_first.holder_secret),
            Scalar::from(0x7777u64),
            Scalar::from(mask_value),
        ],
        Scalar::ZERO,
        0x52455155,
    );
    let (mask, _) = add_request_binding(
        &mut builder,
        holder,
        first.holder_secret,
        nonce,
        mask_value,
        valid_request_digest,
    );
    add_disclosure(
        &mut builder,
        age,
        first.age,
        country,
        first.country,
        mask,
        mask_value,
    );
    if matches!(workload, Workload::W2 | Workload::W3 | Workload::W4) {
        add_range_and_expiry(
            &mut builder,
            age,
            first.age,
            expiry,
            first.expiry,
            current_day,
        );
    }
    let revocation_depth = matches!(workload, Workload::W3 | Workload::W4).then_some(8usize);
    if let Some(depth) = revocation_depth {
        let path = merkle_path(depth);
        let root = merkle_root(valid_first.revocation_index, &path, Scalar::ZERO);
        add_revocation(
            &mut builder,
            revocation_index,
            first.revocation_index,
            root,
            &path,
            if matches!(mutation, Mutation::StaleRoot) {
                8
            } else {
                9
            },
            9,
            matches!(mutation, Mutation::MerklePath),
            matches!(mutation, Mutation::Revoked),
        );
    }
    if workload == Workload::W4 {
        second.age = first.age;
        let second_mac = valid_second.mac();
        let (holder2, age2, _, _, _) = add_credential(&mut builder, &second, second_mac, "second");
        builder.enforce_equal(
            "cross_credential_holder_binding",
            Lc::var(holder),
            Lc::var(holder2),
        );
        builder.enforce_equal(
            "cross_credential_hidden_equality",
            Lc::var(age),
            Lc::var(age2),
        );
    }
    (builder, revocation_depth)
}

pub fn build(
    workload: Workload,
    mutation: Mutation,
    padded_size: usize,
) -> Result<RelationFixture, String> {
    let construction_start = Instant::now();
    if workload == Workload::W0 {
        let n = padded_size;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        let mut c = Vec::with_capacity(n);
        let mut vars = Vec::with_capacity(n);
        for i in 0..n {
            let value = Scalar::from((i & 1) as u64);
            a.push((i, i, Scalar::ONE.to_bytes()));
            b.push((i, i, Scalar::ONE.to_bytes()));
            c.push((i, i, Scalar::ONE.to_bytes()));
            vars.push(value.to_bytes());
        }
        return Ok(RelationFixture {
            a,
            b,
            c,
            vars,
            inputs: vec![Scalar::ZERO.to_bytes()],
            metadata: WorkloadMetadata {
                workload: "W0".into(),
                relation: workload.name().into(),
                raw_constraints: n,
                raw_variables: n,
                witness_elements: n,
                public_inputs: 1,
                padded_size: n,
                q: integer_sqrt(n),
                m: n / integer_sqrt(n),
                fragmented_outputs: integer_sqrt(n),
                padding_constraints: 0,
                padding_variables: 0,
                constraint_composition: BTreeMap::from([("boolean_multiplication".into(), n)]),
                construction_ms: construction_start.elapsed().as_secs_f64() * 1000.0,
                witness_generation_ms: 0.0,
                revocation_depth: None,
                revocation_path_length: None,
                revocation_count: 0,
                revocation_backend: "None".into(),
                issuer_authentication: "none (synthetic regression only)",
                issuer_authentication_assumption: "not a credential workload",
            },
        });
    }

    let witness_start = Instant::now();
    let (builder, revocation_depth) = build_non_synthetic(workload, mutation);
    let witness_generation_ms = witness_start.elapsed().as_secs_f64() * 1000.0;
    let raw_constraints = builder.rows.len();
    let raw_variables = builder.vars.len();
    if !padded_size.is_power_of_two()
        || padded_size < raw_constraints
        || padded_size < raw_variables
    {
        return Err(format!(
            "padded size {padded_size} is smaller than raw shape {raw_constraints}x{raw_variables}"
        ));
    }
    let num_inputs = builder.inputs.len();
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();
    for (row, (left, right, output)) in builder.rows.iter().enumerate() {
        resolve_lc(row, left, padded_size, &mut a);
        resolve_lc(row, right, padded_size, &mut b);
        resolve_lc(row, output, padded_size, &mut c);
    }
    let mut vars: Vec<_> = builder.vars.iter().map(Scalar::to_bytes).collect();
    vars.resize(padded_size, Scalar::ZERO.to_bytes());
    let inputs = builder.inputs.iter().map(Scalar::to_bytes).collect();
    let q = integer_sqrt(padded_size);
    Ok(RelationFixture {
        a,
        b,
        c,
        vars,
        inputs,
        metadata: WorkloadMetadata {
            workload: format!("{workload:?}"),
            relation: workload.name().into(),
            raw_constraints,
            raw_variables,
            witness_elements: raw_variables,
            public_inputs: num_inputs,
            padded_size,
            q,
            m: padded_size / q,
            fragmented_outputs: q,
            padding_constraints: padded_size - raw_constraints,
            padding_variables: padded_size - raw_variables,
            constraint_composition: builder.composition,
            construction_ms: construction_start.elapsed().as_secs_f64() * 1000.0,
            witness_generation_ms,
            revocation_depth,
            revocation_path_length: revocation_depth,
            revocation_count: usize::from(revocation_depth.is_some()),
            revocation_backend: if revocation_depth.is_some() {
                "SparseMerkle".into()
            } else {
                "None".into()
            },
            issuer_authentication: "91-round MiMC7 native-field PRF-MAC with authenticated issuer-key commitment",
            issuer_authentication_assumption: "Only the issuer knows the symmetric key; a registry or issuer authenticates the public key commitment and revocation root",
        },
    })
}

fn resolve_lc(row: usize, lc: &Lc, num_vars: usize, target: &mut Vec<MatrixEntry>) {
    for (wire, coefficient) in &lc.0 {
        if *coefficient == Scalar::ZERO {
            continue;
        }
        let column = match wire {
            Wire::Var(index) => *index,
            Wire::One => num_vars,
            Wire::Input(index) => num_vars + 1 + index,
        };
        target.push((row, column, coefficient.to_bytes()));
    }
}

fn integer_sqrt(n: usize) -> usize {
    1usize << (n.trailing_zeros() as usize / 2)
}

pub fn minimum_log_size(workload: Workload) -> usize {
    // The current fragmented libspartan commitment backend uses a square q x m
    // layout, so only even logarithms are executable without changing proof code.
    for log in [12usize, 14, 16, 18, 20] {
        let n = 1usize << log;
        if build(workload, Mutation::Valid, n).is_ok() {
            return log;
        }
    }
    20
}
