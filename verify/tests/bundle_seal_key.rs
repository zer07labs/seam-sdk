//! Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0) against `seam-verify bundle`: the commitment TCT
//! is signed by an issuer-certified **seal key**, and the evidence-grade check binds its `iat` to the chained
//! `sealed_at` (evidence-bundle.v1 step 4; `seam-commitment-digest.v6.md` §Seal key step 6).
//!
//! **The fixtures' TCTs were re-minted here, and only they.** `fixtures/evidence-bundle/` is the runtime's
//! own export (see `tests/bundle.rs`); its TCTs were signed by the issuer key directly, which S-4 refuses
//! with no backward compatibility. The runtime at #2031 mints `seam-commitment-digest:v6` statements, which
//! `seam-verify bundle` does not read yet (the v6 bundle lands with the writer wave, DECISIONS.md
//! 2026-11-22, A-FW2-3), so a fresh export is not an option. Instead each `commitment.json`'s
//! `signed_artifact` was re-minted the way the runtime's own S-4 token differs from its pre-S-4 one
//! (seam-runtime `S4_COMMITMENT_TCT`): the header, `jti`, `iat`, `exp`, `ver`, `grants` and the statement are
//! unchanged; `iss`/`sub`/`aud`/`cnf` become the seal key's, and the certificate member is added. The seal
//! key is the runtime's test-support `SeededSealKeys::new(issuer_seed)`: seed `sha256("seam.seal-key.fixed.v1"
//! ‖ issuer_seed)`, certified for the UTC hour containing the seal, `[h, h + 3_600_000]` ms. The manifest
//! entry for `commitment.json` was re-hashed; no other byte moved. [`fixture_tcts_are_the_seeded_seal_key_remint`]
//! recomputes every re-minted token from the committed claims, so none of them is typed by hand, and
//! `SEAM_REGEN_BUNDLE_TCT=1` rewrites them.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

/// Issuer seed 7×32 — `full`, `minimal`, `allocated`; 9×32 — `other-issuer`.
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
const FIXTURES: &[(&str, u8)] = &[
    ("full", 7),
    ("minimal", 7),
    ("allocated", 7),
    ("other-issuer", 9),
];

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/evidence-bundle")
        .join(name)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn framed(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn aid_of(k: &SigningKey) -> String {
    format!("aid:pubkey:{}", b64(k.verifying_key().as_bytes()))
}

fn jkt(pk: &[u8]) -> String {
    let jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, b64(pk));
    b64(&Sha256::digest(jwk.as_bytes()))
}

/// Sort every object's members (the runtime's token payloads are serialized key-sorted).
fn sorted(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let b: std::collections::BTreeMap<_, _> =
                m.iter().map(|(k, v)| (k.clone(), sorted(v))).collect();
            serde_json::to_value(b).unwrap()
        }
        serde_json::Value::Array(a) => a.iter().map(sorted).collect(),
        other => other.clone(),
    }
}

fn to_sorted_string(v: &serde_json::Value) -> String {
    fn write(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => {
                let b: std::collections::BTreeMap<_, _> = m.iter().collect();
                out.push('{');
                for (i, (k, v)) in b.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push(':');
                    write(v, out);
                }
                out.push('}');
            }
            serde_json::Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(v, out);
                }
                out.push(']');
            }
            other => out.push_str(&serde_json::to_string(other).unwrap()),
        }
    }
    let mut s = String::new();
    write(&sorted(v), &mut s);
    s
}

/// The runtime's `SeededSealKeys::new(issuer_seed)` certificate for the hour containing `at_ms`.
fn seeded_cert(issuer_seed: [u8; 32], at_ms: u64) -> (SigningKey, serde_json::Value) {
    let issuer = SigningKey::from_bytes(&issuer_seed);
    let seal_seed: [u8; 32] = Sha256::new()
        .chain_update(b"seam.seal-key.fixed.v1")
        .chain_update(issuer_seed)
        .finalize()
        .into();
    let seal = SigningKey::from_bytes(&seal_seed);
    let nb = at_ms - at_ms % 3_600_000;
    let mut cert = Vec::new();
    framed(&mut cert, b"seam.seal-key-cert.v1");
    framed(&mut cert, seal.verifying_key().as_bytes());
    cert.extend_from_slice(&nb.to_le_bytes());
    cert.extend_from_slice(&(nb + 3_600_000).to_le_bytes());
    framed(&mut cert, aid_of(&issuer).as_bytes());
    let sig = issuer.sign(&Sha256::digest(&cert));
    (
        seal,
        serde_json::json!({"cert": b64(&cert), "sig": b64(&sig.to_bytes())}),
    )
}

/// Re-mint `token` under the seeded seal key of `issuer_seed`: same header and claims, `iss`/`sub`/`aud`/
/// `cnf` the seal key's, the certificate member added; `iat` replaced when `iat` is `Some`.
fn remint(token: &str, issuer_seed: [u8; 32], iat: Option<u64>) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let mut claims: serde_json::Value = serde_json::from_slice(&unb64(parts[1])).unwrap();
    if let Some(iat) = iat {
        claims["iat"] = iat.into();
    }
    let at_ms = claims["iat"].as_u64().unwrap() * 1000;
    let (seal, member) = seeded_cert(issuer_seed, at_ms);
    let seal_aid = aid_of(&seal);
    for k in ["iss", "sub", "aud"] {
        claims[k] = seal_aid.clone().into();
    }
    claims["cnf"] = serde_json::json!({"jkt": jkt(seal.verifying_key().as_bytes())});
    claims["ext"]["com.zer07labs.seam.seal-key-cert"] = member;
    let input = format!("{}.{}", parts[0], b64(to_sorted_string(&claims).as_bytes()));
    let sig = seal.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

fn token_of(dir: &Path) -> String {
    let c: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("commitment.json")).unwrap()).unwrap();
    c["signed_artifact"].as_str().unwrap().to_owned()
}

/// Swap the token's bytes inside `commitment.json` (every other byte kept) and re-hash its manifest entry
/// the same way (a string replace of the old sha256 and size).
fn swap_token(dir: &Path, new: &str) {
    let old = token_of(dir);
    let raw = std::fs::read_to_string(dir.join("commitment.json")).unwrap();
    assert_eq!(raw.matches(&old).count(), 1);
    let replaced = raw.replace(&old, new);
    let old_sha = hex(&Sha256::digest(raw.as_bytes()));
    let new_sha = hex(&Sha256::digest(replaced.as_bytes()));
    let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
    let block_old = format!(
        "\"commitment.json\": {{\n      \"sha256\": \"{old_sha}\",\n      \"bytes\": {}\n",
        raw.len()
    );
    let block_new = format!(
        "\"commitment.json\": {{\n      \"sha256\": \"{new_sha}\",\n      \"bytes\": {}\n",
        replaced.len()
    );
    assert_eq!(
        manifest.matches(&block_old).count(),
        1,
        "manifest entry for commitment.json in {dir:?}"
    );
    std::fs::write(dir.join("commitment.json"), replaced).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        manifest.replace(&block_old, &block_new),
    )
    .unwrap();
}

fn copy(from: &str, tag: &str) -> PathBuf {
    let to = std::env::temp_dir().join(format!("seam-sdk-s4-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&to);
    std::fs::create_dir_all(&to).unwrap();
    for e in std::fs::read_dir(fixture(from)).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
    to
}

fn verify(dir: &Path, aid: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(["bundle", dir.to_str().unwrap(), "--issuer", aid])
        .output()
        .expect("run seam-verify");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

#[test]
fn fixture_tcts_are_the_seeded_seal_key_remint() {
    for &(name, seed) in FIXTURES {
        let dir = fixture(name);
        let token = token_of(&dir);
        let fresh = remint(&token, [seed; 32], None);
        if std::env::var_os("SEAM_REGEN_BUNDLE_TCT").is_some() && fresh != token {
            swap_token(&dir, &fresh);
            continue;
        }
        assert_eq!(
            token, fresh,
            "{name}: the committed TCT is not the seeded seal-key re-mint of its own claims"
        );
    }
}

#[test]
fn the_re_minted_bundle_states_the_seal_key_and_the_chained_seal_time() {
    let (code, out) = verify(&fixture("full"), ISSUER);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("certified seal key, issued at the chained seal time"),
        "{out}"
    );
}

/// Evidence grade: a token whose `iat` is inside its certificate window but is not
/// `floor(sealed_at / 1000)` of the chained link is refused, even though it verifies on its own.
#[test]
fn an_iat_that_is_not_the_chained_seal_time_is_refused() {
    let d = copy("full", "iat");
    let token = token_of(&d);
    let claims: serde_json::Value =
        serde_json::from_slice(&unb64(token.split('.').nth(1).unwrap())).unwrap();
    let iat = claims["iat"].as_u64().unwrap();
    // Same hour window, so only the chain binding can refuse it.
    swap_token(&d, &remint(&token, [7; 32], Some(iat + 1)));
    let (code, out) = verify(&d, ISSUER);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("step 4"), "{out}");
    assert!(out.contains("is not the chained seal time"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}

/// No backward compatibility: the issuer-signed shape every TCT had before runtime 0.123.0 is refused.
#[test]
fn an_issuer_signed_tct_is_refused() {
    let d = copy("full", "issuer-signed");
    let token = token_of(&d);
    let parts: Vec<&str> = token.split('.').collect();
    let mut claims: serde_json::Value = serde_json::from_slice(&unb64(parts[1])).unwrap();
    let issuer = SigningKey::from_bytes(&[7; 32]);
    for k in ["iss", "sub", "aud"] {
        claims[k] = ISSUER.into();
    }
    claims["cnf"] = serde_json::json!({"jkt": jkt(issuer.verifying_key().as_bytes())});
    claims["ext"]
        .as_object_mut()
        .unwrap()
        .remove("com.zer07labs.seam.seal-key-cert");
    let input = format!("{}.{}", parts[0], b64(to_sorted_string(&claims).as_bytes()));
    let old = format!("{input}.{}", b64(&issuer.sign(input.as_bytes()).to_bytes()));
    swap_token(&d, &old);
    let (code, out) = verify(&d, ISSUER);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("seal-key-cert certificate"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}
