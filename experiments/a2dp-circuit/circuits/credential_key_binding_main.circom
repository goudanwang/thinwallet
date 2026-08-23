pragma circom 2.0.0;

include "./components/credential_key_binding.circom";

component main {
    public [
        holder_public_key_x,
        holder_public_key_y,
        expected_enrollment_digest
    ]
} = CredentialKeyBinding();
