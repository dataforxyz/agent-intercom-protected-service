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
