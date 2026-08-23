use super::*;

const CREDENTIAL_TYPE: u64 = 0x5457_5343;
const ISSUANCE_EPOCH: u64 = 41;
const REVOCATION_EPOCH: u64 = 73;

fn issuer_key_digest_scalar(index: usize) -> Scalar {
    use sha2::{Digest as _, Sha256};
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[(7 + index) as u8; 32]);
    let digest: [u8; 32] = Sha256::digest(signing_key.verifying_key().to_bytes()).into();
    Scalar::from_bytes_mod_order(digest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RevocationBackend {
    None,
    ExpiryOnly,
    SparseMerkle,
}

impl RevocationBackend {
    pub fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ExpiryOnly => "expiry_only",
            Self::SparseMerkle => "sparse_merkle",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::ExpiryOnly => "ExpiryOnly",
            Self::SparseMerkle => "SparseMerkle",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().replace('-', "_").as_str() {
            "none" => Some(Self::None),
            "expiry_only" | "expiryonly" => Some(Self::ExpiryOnly),
            "sparse_merkle" | "sparsemerkle" => Some(Self::SparseMerkle),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileSWorkload {
    W1,
    W2,
    W3,
    W4,
    WK {
        credentials: usize,
        revocation_count: usize,
        revocation_depth: usize,
        revocation_backend: RevocationBackend,
    },
}

impl ProfileSWorkload {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "S-W1" | "SW1" => Some(Self::W1),
            "S-W2" | "SW2" => Some(Self::W2),
            "S-W3" | "SW3" => Some(Self::W3),
            "S-W4" | "SW4" => Some(Self::W4),
            "WK_52_32_LEGACY" => Some(Self::WK {
                credentials: 52,
                revocation_count: 1,
                revocation_depth: 32,
                revocation_backend: RevocationBackend::SparseMerkle,
            }),
            _ => Self::parse_wk(value),
        }
    }

    fn parse_wk(value: &str) -> Option<Self> {
        if let Some(rest) = value.strip_prefix("WK_k") {
            let (k, rest) = rest.split_once("_r")?;
            let (r, rest) = rest.split_once("_d")?;
            let (d, backend) = rest.split_once('_')?;
            return Some(Self::WK {
                credentials: k.parse().ok()?,
                revocation_count: r.parse().ok()?,
                revocation_depth: d.parse().ok()?,
                revocation_backend: RevocationBackend::parse(backend)?,
            });
        }
        let rest = value.strip_prefix("S-WK-")?;
        let parts: Vec<_> = rest.split('-').collect();
        if parts.len() == 2 {
            // Compatibility lookup only: every historical WK(k,d) fixture had r=1.
            return Some(Self::WK {
                credentials: parts[0].parse().ok()?,
                revocation_count: 1,
                revocation_depth: parts[1].parse().ok()?,
                revocation_backend: RevocationBackend::SparseMerkle,
            });
        }
        if parts.len() < 4 {
            return None;
        }
        Some(Self::WK {
            credentials: parts[0].trim_start_matches('k').parse().ok()?,
            revocation_count: parts[1].trim_start_matches('r').parse().ok()?,
            revocation_depth: parts[2].trim_start_matches('d').parse().ok()?,
            revocation_backend: RevocationBackend::parse(&parts[3..].join("-"))?,
        })
    }

    pub fn name(self) -> String {
        match self {
            Self::W1 => "S-W1".into(),
            Self::W2 => "S-W2".into(),
            Self::W3 => "S-W3".into(),
            Self::W4 => "S-W4".into(),
            Self::WK {
                credentials,
                revocation_count,
                revocation_depth,
                revocation_backend,
            } => format!(
                "S-WK-k{credentials}-r{revocation_count}-d{revocation_depth}-{}",
                revocation_backend.slug()
            ),
        }
    }

    pub fn paper_name(self) -> String {
        match self {
            Self::WK {
                credentials,
                revocation_count,
                revocation_depth,
                revocation_backend,
            } => format!(
                "WK({credentials},{revocation_count},{revocation_depth},{})",
                revocation_backend.label()
            ),
            _ => self.name(),
        }
    }

    pub fn revocation_set(self) -> Vec<usize> {
        match self {
            Self::WK {
                revocation_count, ..
            } => (0..revocation_count).collect(),
            Self::W3 | Self::W4 => vec![0],
            Self::W1 | Self::W2 => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileSMutation {
    Valid,
    Commitment,
    Issuer,
    CredentialType,
    IssuanceEpoch,
    Attribute,
    Holder,
    Nonce,
    Expired,
    Revoked,
    StaleRoot,
    MerklePath,
    CrossCredential,
}

#[derive(Clone)]
struct SignedCredential {
    credential_type: u64,
    issuer_id: u64,
    credential_id: u64,
    holder_secret: u64,
    schema_id: u64,
    age: u64,
    country: u64,
    expiry: u64,
    revocation_id: u64,
    issuance_epoch: u64,
    salt: Scalar,
}

impl SignedCredential {
    fn holder_commitment(&self) -> Scalar {
        native_hash(
            &[Scalar::from(self.holder_secret)],
            Scalar::ZERO,
            0x5348_4f4c,
        )
    }

    fn commitment(&self) -> Scalar {
        native_hash(
            &[
                Scalar::from(self.credential_type),
                Scalar::from(self.issuer_id),
                Scalar::from(self.credential_id),
                self.holder_commitment(),
                Scalar::from(self.schema_id),
                Scalar::from(self.age),
                Scalar::from(self.country),
                Scalar::from(self.expiry),
                Scalar::from(self.revocation_id),
                Scalar::from(self.issuance_epoch),
                self.salt,
            ],
            Scalar::ZERO,
            0x5343_4f4d,
        )
    }
}

fn credential(index: usize) -> SignedCredential {
    SignedCredential {
        credential_type: CREDENTIAL_TYPE,
        issuer_id: 700 + index as u64,
        credential_id: 0x5000 + index as u64,
        holder_secret: 0x5151,
        schema_id: 90 + index as u64,
        age: 24,
        country: 36,
        expiry: 25_000,
        revocation_id: 5 + index as u64,
        issuance_epoch: ISSUANCE_EPOCH,
        salt: Scalar::from(0xa5a5_0000 + index as u64),
    }
}

pub fn native_commitment_for_fixture(index: usize) -> [u8; 32] {
    credential(index).commitment().to_bytes()
}

pub fn native_issuer_key_digest_for_fixture(index: usize) -> [u8; 32] {
    issuer_key_digest_scalar(index).to_bytes()
}

#[derive(Clone)]
pub struct ProfileSReplayRecord {
    pub credential_type: u64,
    pub issuer_id: u64,
    pub credential_id: u64,
    pub holder_secret: u64,
    pub schema_id: u64,
    pub age: u64,
    pub country: u64,
    pub expiry: u64,
    pub revocation_id: u64,
    pub issuance_epoch: u64,
    pub salt: [u8; 32],
    pub issuer_key_digest: [u8; 32],
    pub expected_commitment: [u8; 32],
    pub revocation_path: Vec<[u8; 32]>,
}

struct CredentialWires {
    holder: usize,
    age: usize,
    country: usize,
    expiry: usize,
    revocation_id: usize,
}

fn add_commitment_opening(
    builder: &mut Builder,
    credential: &SignedCredential,
    expected_commitment: Scalar,
    expected_issuer_key_digest: Scalar,
    label: &str,
) -> CredentialWires {
    let credential_id = builder.alloc(Scalar::from(credential.credential_id));
    let holder = builder.alloc(Scalar::from(credential.holder_secret));
    let schema = builder.alloc(Scalar::from(credential.schema_id));
    let age = builder.alloc(Scalar::from(credential.age));
    let country = builder.alloc(Scalar::from(credential.country));
    let expiry = builder.alloc(Scalar::from(credential.expiry));
    let revocation_id = builder.alloc(Scalar::from(credential.revocation_id));
    let salt = builder.alloc(credential.salt);

    let credential_type = builder.public(Scalar::from(credential.credential_type));
    let issuer_id = builder.public(Scalar::from(credential.issuer_id));
    let issuer_key_digest = builder.public(expected_issuer_key_digest);
    let issuance_epoch = builder.public(Scalar::from(credential.issuance_epoch));
    let commitment = builder.public(expected_commitment);

    // This input is intentionally consumed by the application transcript. Keeping it
    // in the R1CS public-input vector prevents issuer-key substitution after verification.
    builder.enforce(
        &format!("issuer_key_digest_public_binding_{label}"),
        Lc::input(issuer_key_digest),
        Lc::constant(Scalar::ONE),
        Lc::input(issuer_key_digest),
    );

    let (holder_commitment, holder_value) = circuit_hash(
        builder,
        &[(Lc::var(holder), Scalar::from(credential.holder_secret))],
        (Lc::constant(Scalar::ZERO), Scalar::ZERO),
        0x5348_4f4c,
        "profile_s_holder_binding",
    );
    let blocks = vec![
        (
            Lc::input(credential_type),
            Scalar::from(credential.credential_type),
        ),
        (Lc::input(issuer_id), Scalar::from(credential.issuer_id)),
        (
            Lc::var(credential_id),
            Scalar::from(credential.credential_id),
        ),
        (holder_commitment, holder_value),
        (Lc::var(schema), Scalar::from(credential.schema_id)),
        (Lc::var(age), Scalar::from(credential.age)),
        (Lc::var(country), Scalar::from(credential.country)),
        (Lc::var(expiry), Scalar::from(credential.expiry)),
        (
            Lc::var(revocation_id),
            Scalar::from(credential.revocation_id),
        ),
        (
            Lc::input(issuance_epoch),
            Scalar::from(credential.issuance_epoch),
        ),
        (Lc::var(salt), credential.salt),
    ];
    let (computed, _) = circuit_hash(
        builder,
        &blocks,
        (Lc::constant(Scalar::ZERO), Scalar::ZERO),
        0x5343_4f4d,
        "profile_s_commitment_opening",
    );
    builder.enforce_equal(
        &format!("profile_s_commitment_equality_{label}"),
        computed,
        Lc::input(commitment),
    );
    CredentialWires {
        holder,
        age,
        country,
        expiry,
        revocation_id,
    }
}

fn add_profile_s_revocation_with_path(
    builder: &mut Builder,
    credential: &SignedCredential,
    revocation_id: usize,
    _depth: usize,
    mutation: ProfileSMutation,
    path: Vec<Scalar>,
) {
    let public_revocation_id = builder.public(Scalar::from(credential.revocation_id));
    builder.enforce_equal(
        "profile_s_public_revocation_identifier",
        Lc::var(revocation_id),
        Lc::input(public_revocation_id),
    );
    let root = merkle_root(credential.revocation_id, &path, Scalar::ZERO);
    add_revocation(
        builder,
        revocation_id,
        credential.revocation_id,
        root,
        &path,
        if mutation == ProfileSMutation::StaleRoot {
            REVOCATION_EPOCH - 1
        } else {
            REVOCATION_EPOCH
        },
        REVOCATION_EPOCH,
        mutation == ProfileSMutation::MerklePath,
        mutation == ProfileSMutation::Revoked,
    );
}

fn add_profile_s_revocation(
    builder: &mut Builder,
    credential: &SignedCredential,
    revocation_id: usize,
    depth: usize,
    mutation: ProfileSMutation,
) {
    add_profile_s_revocation_with_path(
        builder,
        credential,
        revocation_id,
        depth,
        mutation,
        merkle_path(depth),
    );
}

fn empty_sparse_path(depth: usize) -> Vec<Scalar> {
    let mut current = Scalar::ZERO;
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        path.push(current);
        current = native_hash(&[current, current], Scalar::ZERO, 0x4d45524b);
    }
    path
}

pub fn fixture_revocation_material(
    revocation_count: usize,
    credential_index: usize,
    depth: usize,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let path = if revocation_count > 1 {
        empty_sparse_path(depth)
    } else {
        merkle_path(depth)
    };
    let root = merkle_root(5 + credential_index as u64, &path, Scalar::ZERO);
    (
        path.into_iter().map(|value| value.to_bytes()).collect(),
        root.to_bytes(),
    )
}

fn build_standard(
    workload: ProfileSWorkload,
    mutation: ProfileSMutation,
) -> (Builder, Option<usize>) {
    let mut builder = Builder::new();
    let count = if workload == ProfileSWorkload::W4 {
        2
    } else {
        1
    };
    let mut credentials: Vec<_> = (0..count).map(credential).collect();
    let valid = credentials.clone();
    let mut nonce = 0x7777;
    let mut current_day = 24_000;
    match mutation {
        ProfileSMutation::Issuer => credentials[0].issuer_id += 1,
        ProfileSMutation::CredentialType => credentials[0].credential_type += 1,
        ProfileSMutation::IssuanceEpoch => credentials[0].issuance_epoch += 1,
        ProfileSMutation::Attribute => credentials[0].age += 1,
        ProfileSMutation::Holder => credentials[0].holder_secret += 1,
        ProfileSMutation::Nonce => nonce += 1,
        ProfileSMutation::Expired => current_day = 26_000,
        ProfileSMutation::CrossCredential if count > 1 => credentials[1].holder_secret += 1,
        _ => {}
    }
    let mut wires = Vec::new();
    for (index, item) in credentials.iter().enumerate() {
        let expected = if mutation == ProfileSMutation::Commitment && index == 0 {
            valid[index].commitment() + Scalar::ONE
        } else {
            valid[index].commitment()
        };
        wires.push(add_commitment_opening(
            &mut builder,
            item,
            expected,
            issuer_key_digest_scalar(index),
            &format!("credential_{index}"),
        ));
    }
    let mask_value = match workload {
        ProfileSWorkload::W1 => 1,
        ProfileSWorkload::W2 | ProfileSWorkload::W3 => 2,
        ProfileSWorkload::W4 => 0,
        ProfileSWorkload::WK { .. } => unreachable!(),
    };
    let expected_request = native_hash(
        &[
            Scalar::from(valid[0].holder_secret),
            Scalar::from(0x7777u64),
            Scalar::from(mask_value),
        ],
        Scalar::ZERO,
        0x5245_5155,
    );
    let (mask, _) = add_request_binding(
        &mut builder,
        wires[0].holder,
        credentials[0].holder_secret,
        nonce,
        mask_value,
        expected_request,
    );
    add_disclosure(
        &mut builder,
        wires[0].age,
        credentials[0].age,
        wires[0].country,
        credentials[0].country,
        mask,
        mask_value,
    );
    if matches!(
        workload,
        ProfileSWorkload::W2 | ProfileSWorkload::W3 | ProfileSWorkload::W4
    ) {
        add_range_and_expiry(
            &mut builder,
            wires[0].age,
            credentials[0].age,
            wires[0].expiry,
            credentials[0].expiry,
            current_day,
        );
    }
    let depth = matches!(workload, ProfileSWorkload::W3 | ProfileSWorkload::W4).then_some(8);
    if let Some(depth) = depth {
        add_profile_s_revocation(
            &mut builder,
            &credentials[0],
            wires[0].revocation_id,
            depth,
            mutation,
        );
    }
    if count == 2 {
        builder.enforce_equal(
            "cross_credential_holder_binding",
            Lc::var(wires[0].holder),
            Lc::var(wires[1].holder),
        );
        builder.enforce_equal(
            "cross_credential_hidden_equality",
            Lc::var(wires[0].age),
            Lc::var(wires[1].age),
        );
    }
    (builder, depth)
}

fn build_scaling(
    credentials_count: usize,
    revocation_count: usize,
    depth: usize,
    backend: RevocationBackend,
    replay_records: Option<&[ProfileSReplayRecord]>,
) -> Result<(Builder, Option<usize>), String> {
    let mut builder = Builder::new();
    if replay_records.is_some_and(|records| records.len() != credentials_count) {
        return Err("compact replay credential count mismatch".into());
    }
    let scalar = |bytes: [u8; 32], label: &str| {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or_else(|| format!("non-canonical replay scalar: {label}"))
    };
    let credentials: Vec<_> = if let Some(records) = replay_records {
        records
            .iter()
            .map(|record| {
                Ok(SignedCredential {
                    credential_type: record.credential_type,
                    issuer_id: record.issuer_id,
                    credential_id: record.credential_id,
                    holder_secret: record.holder_secret,
                    schema_id: record.schema_id,
                    age: record.age,
                    country: record.country,
                    expiry: record.expiry,
                    revocation_id: record.revocation_id,
                    issuance_epoch: record.issuance_epoch,
                    salt: scalar(record.salt, "commitment salt")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        (0..credentials_count).map(credential).collect()
    };
    let mut wires = Vec::new();
    for (index, item) in credentials.iter().enumerate() {
        let (expected_commitment, issuer_key_digest) = if let Some(records) = replay_records {
            (
                scalar(records[index].expected_commitment, "credential commitment")?,
                scalar(records[index].issuer_key_digest, "issuer key digest")?,
            )
        } else {
            (item.commitment(), issuer_key_digest_scalar(index))
        };
        wires.push(add_commitment_opening(
            &mut builder,
            item,
            expected_commitment,
            issuer_key_digest,
            &format!("credential_{index}"),
        ));
        if index > 0 {
            builder.enforce_equal(
                "wk_cross_holder_binding",
                Lc::var(wires[0].holder),
                Lc::var(wires[index].holder),
            );
            builder.enforce_equal(
                "wk_cross_attribute_equality",
                Lc::var(wires[0].age),
                Lc::var(wires[index].age),
            );
        }
    }
    let expected_request = native_hash(
        &[
            Scalar::from(credentials[0].holder_secret),
            Scalar::from(0x7777u64),
            Scalar::ZERO,
        ],
        Scalar::ZERO,
        0x5245_5155,
    );
    let (mask, _) = add_request_binding(
        &mut builder,
        wires[0].holder,
        credentials[0].holder_secret,
        0x7777,
        0,
        expected_request,
    );
    add_disclosure(
        &mut builder,
        wires[0].age,
        credentials[0].age,
        wires[0].country,
        credentials[0].country,
        mask,
        0,
    );
    add_range_and_expiry(
        &mut builder,
        wires[0].age,
        credentials[0].age,
        wires[0].expiry,
        credentials[0].expiry,
        24_000,
    );
    if backend == RevocationBackend::SparseMerkle {
        for index in 0..revocation_count {
            let path = if let Some(records) = replay_records {
                records[index]
                    .revocation_path
                    .iter()
                    .map(|value| scalar(*value, "revocation path"))
                    .collect::<Result<Vec<_>, String>>()?
            } else if revocation_count > 1 {
                empty_sparse_path(depth)
            } else {
                merkle_path(depth)
            };
            if path.len() != depth {
                return Err("compact replay revocation path length mismatch".into());
            }
            add_profile_s_revocation_with_path(
                &mut builder,
                &credentials[index],
                wires[index].revocation_id,
                depth,
                ProfileSMutation::Valid,
                path,
            );
        }
    }
    Ok((
        builder,
        (backend == RevocationBackend::SparseMerkle && revocation_count > 0).then_some(depth),
    ))
}

fn build_profile_s_inner(
    workload: ProfileSWorkload,
    mutation: ProfileSMutation,
    padded_size: usize,
    replay_records: Option<&[ProfileSReplayRecord]>,
) -> Result<RelationFixture, String> {
    let construction_start = Instant::now();
    let witness_start = Instant::now();
    let (builder, revocation_depth) = match workload {
        ProfileSWorkload::WK {
            credentials,
            revocation_count,
            revocation_depth,
            revocation_backend,
        } => {
            let sparse_shape_valid = revocation_backend == RevocationBackend::SparseMerkle
                && revocation_count > 0
                && revocation_depth > 0;
            let non_merkle_shape_valid = matches!(
                revocation_backend,
                RevocationBackend::None | RevocationBackend::ExpiryOnly
            ) && revocation_count == 0
                && revocation_depth == 0;
            if credentials == 0
                || revocation_count > credentials
                || !(sparse_shape_valid || non_merkle_shape_valid)
                || mutation != ProfileSMutation::Valid
            {
                return Err(
                    "WK requires k>0, r<=k, a consistent backend/depth, and the Valid fixture"
                        .into(),
                );
            }
            build_scaling(
                credentials,
                revocation_count,
                revocation_depth,
                revocation_backend,
                replay_records,
            )?
        }
        _ => {
            if replay_records.is_some() {
                return Err("compact replay currently requires WK".into());
            }
            build_standard(workload, mutation)
        }
    };
    let witness_generation_ms = witness_start.elapsed().as_secs_f64() * 1000.0;
    let raw_constraints = builder.rows.len();
    let raw_variables = builder.vars.len();
    let public_inputs = builder.inputs.len();
    if !padded_size.is_power_of_two()
        || padded_size < raw_constraints
        || padded_size < raw_variables
    {
        return Err(format!(
            "padded size {padded_size} is smaller than raw shape {raw_constraints}x{raw_variables}"
        ));
    }
    let Builder {
        vars: builder_vars,
        inputs: builder_inputs,
        rows,
        composition,
    } = builder;
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();
    for (row, (left, right, output)) in rows.into_iter().enumerate() {
        resolve_lc(row, &left, padded_size, &mut a);
        resolve_lc(row, &right, padded_size, &mut b);
        resolve_lc(row, &output, padded_size, &mut c);
    }
    let mut vars: Vec<_> = builder_vars
        .into_iter()
        .map(|value| value.to_bytes())
        .collect();
    vars.resize(padded_size, Scalar::ZERO.to_bytes());
    let inputs = builder_inputs
        .into_iter()
        .map(|value| value.to_bytes())
        .collect();
    let q = integer_sqrt(padded_size);
    Ok(RelationFixture {
        a,
        b,
        c,
        vars,
        inputs,
        metadata: WorkloadMetadata {
            workload: workload.name(),
            relation: "public-key issuer-authenticated commitment profile".into(),
            raw_constraints,
            raw_variables,
            witness_elements: raw_variables,
            public_inputs,
            padded_size,
            q,
            m: padded_size / q,
            fragmented_outputs: q,
            padding_constraints: padded_size - raw_constraints,
            padding_variables: padded_size - raw_variables,
            constraint_composition: composition,
            construction_ms: construction_start.elapsed().as_secs_f64() * 1000.0,
            witness_generation_ms,
            revocation_depth,
            revocation_path_length: revocation_depth,
            revocation_count: workload.revocation_set().len(),
            revocation_backend: match workload {
                ProfileSWorkload::WK {
                    revocation_backend, ..
                } => revocation_backend.label().into(),
                ProfileSWorkload::W3 | ProfileSWorkload::W4 => "SparseMerkle".into(),
                ProfileSWorkload::W1 | ProfileSWorkload::W2 => "None".into(),
            },
            issuer_authentication: "Ed25519 issuer signature verified outside SNARK over a hiding native-field commitment",
            issuer_authentication_assumption: "RFC 8032 EUF-CMA plus strict ed25519-dalek verification, authenticated issuer registry, MiMC7 commitment binding/hiding, and application transcript binding",
        },
    })
}

pub fn build_profile_s(
    workload: ProfileSWorkload,
    mutation: ProfileSMutation,
    padded_size: usize,
) -> Result<RelationFixture, String> {
    build_profile_s_inner(workload, mutation, padded_size, None)
}

pub fn build_profile_s_from_records(
    workload: ProfileSWorkload,
    padded_size: usize,
    records: &[ProfileSReplayRecord],
) -> Result<RelationFixture, String> {
    build_profile_s_inner(
        workload,
        ProfileSMutation::Valid,
        padded_size,
        Some(records),
    )
}

pub fn minimum_profile_s_log(workload: ProfileSWorkload) -> usize {
    for log in 12usize..=20 {
        if build_profile_s(workload, ProfileSMutation::Valid, 1usize << log).is_ok() {
            return log;
        }
    }
    20
}
