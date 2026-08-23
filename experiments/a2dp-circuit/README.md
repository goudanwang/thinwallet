# A2DP Circuit Toolchain Sanity Experiment

This directory is an isolated Circom 2 + circomlib + snarkjs toolchain test.

It is not an A2DP prototype. It does not implement credentials, holder authorization, issuer signatures, holder signatures, selective disclosure, secret sharing, private witness generation, or delegated proving.

The only circuit is a minimal multiplication sanity check:

```text
c = a * b
```

with sample input:

```json
{
  "a": "3",
  "b": "7"
}
```

## Files

```text
experiments/a2dp-circuit/
├── README.md
├── package.json
├── .gitignore
├── circuits/sanity_multiplier.circom
├── inputs/sanity_multiplier.json
├── scripts/check_env.sh
├── scripts/build_sanity.sh
├── build/.gitkeep
└── results/.gitkeep
```

## Dependencies

The experiment expects the following commands to be available:

* `circom`
* `node`
* `npm`
* `python3`

The npm dependencies are pinned in `package.json`:

* `snarkjs`
* `circomlib`

Install npm dependencies from this directory before building:

```sh
npm install
```

This task did not install dependencies.

## Environment Check

```sh
bash scripts/check_env.sh
```

If `circom` is missing, the build is blocked. The scripts do not fabricate generated artifacts or proof results.

## Build Sanity Proof

```sh
bash scripts/build_sanity.sh
```

The build script writes all generated files to `build/` and performs:

1. Circom compilation.
2. Witness generation.
3. R1CS info extraction.
4. Groth16 Powers of Tau preparation.
5. Groth16 setup.
6. Proof generation.
7. Proof verification.

## Outputs

Generated outputs are ignored by Git under `build/`. The important expected outputs include:

```text
build/sanity_multiplier.r1cs
build/sanity_multiplier_js/
build/sanity_multiplier.wtns
build/r1cs_info.txt
build/pot12_final.ptau
build/sanity_multiplier_final.zkey
build/verification_key.json
build/proof.json
build/public.json
build/verify.log
```

The constraint count should be read from `build/r1cs_info.txt` after a successful build.
