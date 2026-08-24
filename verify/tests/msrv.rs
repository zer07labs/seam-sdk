//! The declared MSRV must be at least what the dependency graph actually requires.
//!
//! This exists because the MSRV was *guessed* the first time it was written down — 1.74, from
//! remembering what `ed25519-dalek` needed — and the real floor was **1.85**, imposed by `prost`,
//! `base64ct` and `zeroize`. A published crate carrying a `rust-version` that is too low is worse
//! than one carrying none: absent is honestly silent, whereas a wrong number reads as a checked
//! promise and a consumer only finds out from a compile error.
//!
//! Pinning a number would not be enough either. These are ordinary third-party crates that raise
//! their own MSRVs on their own schedule, without anyone editing this manifest — the same shape as
//! `python/tests/test_protobuf_floor.py`, whose floor moves whenever buf's remote plugins do. So the
//! requirement is **derived from the resolved graph and asserted**, and a dependency bump that
//! outruns the declared floor fails here rather than in a consumer's build.

use std::process::Command;

fn semver(v: &str) -> Vec<u32> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

#[test]
fn the_declared_msrv_covers_every_dependency() {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed");

    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("cargo metadata emits JSON");
    let packages = meta["packages"].as_array().expect("packages array");

    let mut declared: Option<String> = None;
    let mut required: Option<(String, String)> = None; // (version, crate name)

    for p in packages {
        let name = p["name"].as_str().unwrap_or_default();
        let Some(rv) = p["rust_version"].as_str() else {
            continue;
        };
        if name == "seam-verify" {
            declared = Some(rv.to_string());
            continue;
        }
        let higher = required
            .as_ref()
            .is_none_or(|(cur, _)| semver(rv) > semver(cur));
        if higher {
            required = Some((rv.to_string(), name.to_string()));
        }
    }

    let declared = declared.expect(
        "seam-verify must declare `rust-version` in Cargo.toml — a published crate without one \
         gives consumers no MSRV signal at all",
    );
    let (required_version, by) = required.expect("some dependency declares a rust-version");

    assert!(
        semver(&declared) >= semver(&required_version),
        "declared MSRV {declared} is BELOW what the dependency graph requires ({required_version}, \
         from `{by}`). Raise `rust-version` in verify/Cargo.toml to at least {required_version} — \
         a floor that is too low is a promise this crate cannot keep, and a consumer discovers it \
         as a compile error."
    );
}
