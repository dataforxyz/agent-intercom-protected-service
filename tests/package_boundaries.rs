use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            if entry.file_name() != "target" && entry.file_name() != ".git" {
                collect_files(&entry.path(), files);
            }
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
}

#[test]
fn rust_package_is_library_only_publish_disabled_and_dependency_free() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(manifest.contains("publish = false"));
    assert!(manifest.contains("build = false"));
    assert!(manifest.contains("autobins = false"));
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[build-dependencies]"));
    assert!(!root().join("build.rs").exists());
    assert!(!root().join("src/main.rs").exists());
    assert!(!root().join("src/bin").exists());
    assert!(fs::read_to_string(root().join("src/lib.rs"))
        .unwrap()
        .contains("#![forbid(unsafe_code)]"));
}

#[test]
fn npm_package_is_private_data_only_and_has_exact_declared_files() {
    let package = fs::read_to_string(root().join("package.json")).unwrap();
    assert!(
        package.contains("\"name\": \"@dataforxyz/agent-intercom-protected-service-contracts\"")
    );
    assert!(package.contains("\"private\": true"));
    for forbidden in [
        "\"main\"",
        "\"module\"",
        "\"browser\"",
        "\"bin\"",
        "\"scripts\"",
        "\"dependencies\"",
        "\"devDependencies\"",
        "\"optionalDependencies\"",
        "\"peerDependencies\"",
        "\"bundledDependencies\"",
    ] {
        assert!(
            !package.contains(forbidden),
            "forbidden npm key: {forbidden}"
        );
    }
    for packed_file in [
        "index.d.ts",
        "schemas/provisioning-request.v1.schema.json",
        "schemas/systemd-hardening.v1.schema.json",
        "data/systemd-hardening.v1.json",
        "README.md",
        "LICENSE",
    ] {
        assert!(package.contains(&format!("\"{packed_file}\"")));
    }

    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    assert!(!declarations.contains("export const"));
    assert!(!declarations.contains("export function"));
}

#[test]
fn repository_has_no_javascript_native_service_or_executable_source() {
    let mut files = Vec::new();
    collect_files(&root(), &mut files);
    for file in files {
        let relative = file.strip_prefix(root()).unwrap();
        let name = relative.to_string_lossy();
        assert!(
            !name.ends_with(".js")
                && !name.ends_with(".mjs")
                && !name.ends_with(".cjs")
                && !name.ends_with(".node")
                && !name.ends_with(".service"),
            "forbidden runnable/native/service file: {name}"
        );
    }
}

#[test]
fn dsse_surface_is_format_only_without_crypto_policy_roots_or_runtime_wiring() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    for forbidden in ["base64 =", "ed25519", "openssl", "ring =", "rsa =", "sha2"] {
        assert!(
            !manifest.contains(forbidden),
            "crypto/encoding dependency entered the format-only crate: {forbidden}"
        );
    }

    let dsse = fs::read_to_string(root().join("src/dsse.rs")).unwrap();
    for forbidden in [
        "std::fs",
        "std::net",
        "std::os",
        "std::process",
        "Command::",
        "TcpStream",
        "VerifiedReleasePolicy",
        "ReleasePolicy",
        "TrustArgument",
        "TrustResult",
        "verify_install_input",
        "Observer",
        "Integration",
    ] {
        assert!(
            !dsse.contains(forbidden),
            "DSSE format module crossed its inert boundary: {forbidden}"
        );
    }

    for forbidden_path in [
        "src/release_policy.rs",
        "src/verified_release_policy.rs",
        "src/observer.rs",
        "src/system.rs",
        "src/integration.rs",
        "src/runtime.rs",
        "src/install.rs",
        "src/data",
        "src/npm",
        "data/dsse",
        "data/keys",
        "data/trust-roots",
        "tests/fixtures/dsse",
        "tests/keys",
        "tests/trust-roots",
    ] {
        assert!(
            !root().join(forbidden_path).exists(),
            "forbidden production/test trust or runtime surface: {forbidden_path}"
        );
    }

    let package = fs::read_to_string(root().join("package.json")).unwrap();
    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    assert!(!package.to_ascii_lowercase().contains("dsse"));
    assert!(!declarations.to_ascii_lowercase().contains("dsse"));
    assert!(!declarations.contains("VerifiedReleasePolicy"));
}

#[test]
fn release_inventory_surface_is_rust_only_untrusted_data_without_runtime_or_policy_wiring() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[build-dependencies]"));

    let source = fs::read_to_string(root().join("src/untrusted_release_inventory.rs")).unwrap();
    for required in [
        "pub struct UntrustedReleaseInventoryV1",
        "pub struct UntrustedArtifactClaim",
        "pub struct UntrustedDigestClaim",
        "pub struct UntrustedEvidenceClaim",
        "pub enum UntrustedEvidenceTag",
        "MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES: usize = 32_768",
        "MAX_UNTRUSTED_EVIDENCE_CLAIMS: usize = 32",
        "subject_digest != *installable_digest",
    ] {
        assert!(source.contains(required), "inventory omitted {required}");
    }
    for forbidden in [
        "use crate::dsse",
        "use crate::base64",
        "std::fs",
        "std::io",
        "std::net",
        "std::os",
        "std::path",
        "std::process",
        "std::time",
        "Command::",
        "TcpStream",
        "File::",
        "SystemTime",
        "VerifiedRelease",
        "TrustedRelease",
        "AcceptedRelease",
        "AuthorizedRelease",
        "ReleasePolicy",
        "verify_install_input",
        "pre_authentication_encoding",
        "signature_bytes",
        "key_id",
    ] {
        assert!(
            !source.contains(forbidden),
            "inventory crossed its inert untrusted boundary: {forbidden}"
        );
    }

    let library = fs::read_to_string(root().join("src/lib.rs")).unwrap();
    assert!(library.contains("mod untrusted_release_inventory;"));
    assert!(library.contains("canonicalize_untrusted_release_inventory"));

    for forbidden_path in [
        "schemas/untrusted-release-inventory.v1.schema.json",
        "schemas/release-inventory.v1.schema.json",
        "data/untrusted-release-inventory.v1.json",
        "data/release-inventory.v1.json",
        "tests/fixtures/untrusted-release-inventory",
        "tests/fixtures/release-inventory",
        "src/release_inventory_policy.rs",
        "src/release_inventory_runtime.rs",
        "src/release_inventory_service.rs",
    ] {
        assert!(
            !root().join(forbidden_path).exists(),
            "forbidden inventory exposure/runtime surface: {forbidden_path}"
        );
    }

    let package = fs::read_to_string(root().join("package.json")).unwrap();
    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    for forbidden in [
        "untrusted-release-inventory",
        "release-inventory",
        "UntrustedReleaseInventory",
        "UntrustedArtifactClaim",
        "UntrustedDigestClaim",
        "UntrustedEvidenceClaim",
    ] {
        assert!(
            !package.contains(forbidden),
            "inventory entered npm package metadata: {forbidden}"
        );
        assert!(
            !declarations.contains(forbidden),
            "inventory entered TypeScript declarations: {forbidden}"
        );
    }
}

#[test]
fn transparency_checkpoint_surface_is_rust_only_untrusted_data_without_proof_or_state_wiring() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[build-dependencies]"));

    let source =
        fs::read_to_string(root().join("src/untrusted_transparency_checkpoint.rs")).unwrap();
    for required in [
        "pub struct UntrustedTransparencyCheckpointV1",
        "MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES: usize = 4_096",
        "canonicalize_untrusted_transparency_checkpoint",
        "tree_size must be a canonical unsigned JSON u64",
    ] {
        assert!(source.contains(required), "checkpoint omitted {required}");
    }
    for forbidden in [
        "use crate::dsse",
        "use crate::base64",
        "std::fs",
        "std::io",
        "std::net",
        "std::os",
        "std::path",
        "std::process",
        "std::time",
        "Command::",
        "TcpStream",
        "File::",
        "SystemTime",
        "InclusionProof",
        "ConsistencyProof",
        "Witness",
        "Quorum",
        "TrustedCheckpoint",
        "VerifiedCheckpoint",
        "AcceptedCheckpoint",
        "ActiveLog",
        "ReleasePolicy",
        "verify",
        "persist",
    ] {
        assert!(
            !source.contains(forbidden),
            "checkpoint crossed its inert untrusted boundary: {forbidden}"
        );
    }

    for forbidden_path in [
        "schemas/untrusted-transparency-checkpoint.v1.schema.json",
        "schemas/transparency-checkpoint.v1.schema.json",
        "data/untrusted-transparency-checkpoint.v1.json",
        "data/transparency-checkpoint.v1.json",
        "tests/fixtures/untrusted-transparency-checkpoint",
        "tests/fixtures/transparency-checkpoint",
        "src/transparency_verifier.rs",
        "src/transparency_state.rs",
        "src/witness.rs",
        "src/inclusion_proof.rs",
        "src/consistency_proof.rs",
    ] {
        assert!(
            !root().join(forbidden_path).exists(),
            "forbidden checkpoint trust/proof/runtime surface: {forbidden_path}"
        );
    }

    let package = fs::read_to_string(root().join("package.json")).unwrap();
    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    for forbidden in [
        "transparency-checkpoint",
        "UntrustedTransparencyCheckpoint",
        "canonicalize_untrusted_transparency_checkpoint",
    ] {
        assert!(
            !package.contains(forbidden),
            "checkpoint entered npm metadata: {forbidden}"
        );
        assert!(
            !declarations.contains(forbidden),
            "checkpoint entered declarations: {forbidden}"
        );
    }
}

#[test]
fn transparency_consistency_surface_is_rust_only_untrusted_data_without_verifier_or_state_wiring() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[build-dependencies]"));

    let source =
        fs::read_to_string(root().join("src/untrusted_transparency_consistency_proof.rs")).unwrap();
    for required in [
        "pub struct UntrustedTransparencyConsistencyProofV1",
        "MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES: usize = 65_536",
        "MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_NODES: usize = 64",
        "canonicalize_untrusted_transparency_consistency_proof",
        "proof must contain 0..=64 opaque node claims",
    ] {
        assert!(
            source.contains(required),
            "consistency claim omitted {required}"
        );
    }
    for forbidden in [
        "use crate::dsse",
        "use crate::base64",
        "std::fs",
        "std::io",
        "std::net",
        "std::os",
        "std::path",
        "std::process",
        "std::time",
        "Command::",
        "TcpStream",
        "File::",
        "SystemTime",
        "TrustedConsistency",
        "VerifiedConsistency",
        "AcceptedConsistency",
        "ActiveLog",
        "Witness",
        "Quorum",
        "Merkle",
        "verify_consistency",
        "persist",
    ] {
        assert!(
            !source.contains(forbidden),
            "consistency claim crossed its inert boundary: {forbidden}"
        );
    }

    for forbidden_path in [
        "schemas/untrusted-transparency-consistency-proof.v1.schema.json",
        "schemas/transparency-consistency-proof.v1.schema.json",
        "data/untrusted-transparency-consistency-proof.v1.json",
        "data/transparency-consistency-proof.v1.json",
        "tests/fixtures/untrusted-transparency-consistency-proof",
        "tests/fixtures/transparency-consistency-proof",
        "src/transparency_verifier.rs",
        "src/transparency_state.rs",
        "src/witness.rs",
        "src/merkle.rs",
    ] {
        assert!(
            !root().join(forbidden_path).exists(),
            "forbidden consistency trust/runtime surface: {forbidden_path}"
        );
    }

    let package = fs::read_to_string(root().join("package.json")).unwrap();
    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    for forbidden in [
        "transparency-consistency-proof",
        "UntrustedTransparencyConsistencyProof",
        "canonicalize_untrusted_transparency_consistency_proof",
    ] {
        assert!(
            !package.contains(forbidden),
            "consistency claim entered npm metadata: {forbidden}"
        );
        assert!(
            !declarations.contains(forbidden),
            "consistency claim entered declarations: {forbidden}"
        );
    }
}

#[test]
fn transparency_inclusion_surface_is_rust_only_untrusted_data_without_verifier_or_state_wiring() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[build-dependencies]"));

    let source =
        fs::read_to_string(root().join("src/untrusted_transparency_inclusion_proof.rs")).unwrap();
    for required in [
        "pub struct UntrustedTransparencyInclusionProofV1",
        "MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES: usize = 65_536",
        "MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_NODES: usize = 64",
        "canonicalize_untrusted_transparency_inclusion_proof",
        "leaf_index must be a canonical unsigned JSON u64",
        "proof must contain 0..=64 opaque node claims",
    ] {
        assert!(
            source.contains(required),
            "inclusion claim omitted {required}"
        );
    }
    for forbidden in [
        "use crate::dsse",
        "use crate::base64",
        "std::fs",
        "std::io",
        "std::net",
        "std::os",
        "std::path",
        "std::process",
        "std::time",
        "Command::",
        "TcpStream",
        "File::",
        "SystemTime",
        "TrustedInclusion",
        "VerifiedInclusion",
        "AcceptedInclusion",
        "ActiveLog",
        "Witness",
        "Quorum",
        "Merkle",
        "verify_inclusion",
        "manifest_digest",
        "release_tuple",
        "persist",
    ] {
        assert!(
            !source.contains(forbidden),
            "inclusion claim crossed its inert boundary: {forbidden}"
        );
    }

    for forbidden_path in [
        "schemas/untrusted-transparency-inclusion-proof.v1.schema.json",
        "schemas/transparency-inclusion-proof.v1.schema.json",
        "data/untrusted-transparency-inclusion-proof.v1.json",
        "data/transparency-inclusion-proof.v1.json",
        "tests/fixtures/untrusted-transparency-inclusion-proof",
        "tests/fixtures/transparency-inclusion-proof",
        "src/transparency_verifier.rs",
        "src/transparency_state.rs",
        "src/witness.rs",
        "src/merkle.rs",
    ] {
        assert!(
            !root().join(forbidden_path).exists(),
            "forbidden inclusion trust/runtime surface: {forbidden_path}"
        );
    }

    let package = fs::read_to_string(root().join("package.json")).unwrap();
    let declarations = fs::read_to_string(root().join("index.d.ts")).unwrap();
    for forbidden in [
        "transparency-inclusion-proof",
        "UntrustedTransparencyInclusionProof",
        "canonicalize_untrusted_transparency_inclusion_proof",
    ] {
        assert!(
            !package.contains(forbidden),
            "inclusion claim entered npm metadata: {forbidden}"
        );
        assert!(
            !declarations.contains(forbidden),
            "inclusion claim entered declarations: {forbidden}"
        );
    }
}

#[test]
fn local_package_proof_requires_exact_direct_tools_before_packaging() {
    let checker = fs::read_to_string(root().join("tools/check-reproducible-packages.sh")).unwrap();
    for required in [
        "RUSTUP_TOOLCHAIN overrides are forbidden",
        "*/rustup|*/rustup.exe)",
        "[ \"$2\" != 1.97.1 ]",
        "[ \"$node_version\" != v26.3.0 ]",
        "[ \"$npm_version\" != 11.16.0 ]",
        "RUSTC=\"$rustc_path\"",
    ] {
        assert!(checker.contains(required), "checker omitted {required}");
    }
    assert!(!checker.contains("export RUSTUP_TOOLCHAIN"));
    assert!(!checker.contains("rustup toolchain"));

    let first_package = checker.find("\"$cargo_path\" package").unwrap();
    for version_check in [
        "rustc_version=",
        "cargo_version=",
        "node_version=",
        "npm_version=",
    ] {
        assert!(
            checker.find(version_check).unwrap() < first_package,
            "{version_check} must precede the first package command"
        );
    }
}

#[test]
fn hosted_ci_pins_ephemeral_tool_acquisition_exactly() {
    let workflow = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "runs-on: ubuntu-24.04",
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1",
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0",
        "node-version: 26.3.0",
        "rustup toolchain install 1.97.1 --profile minimal --component rustfmt,clippy --no-self-update",
        "npm install --global npm@11.16.0 --ignore-scripts",
        "test \"$(node --version)\" = v26.3.0",
        "test \"$(npm --version)\" = 11.16.0",
    ] {
        assert!(workflow.contains(required), "workflow omitted {required}");
    }
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("actions/checkout@v"));
    assert!(!workflow.contains("actions/setup-node@v"));
}
