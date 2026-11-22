//! The Gate block v1: the `0x05` trailer body and `seam-gate-digest:v1` (v6 commitment field 10).
//!
//! Written from `seam-runtime/docs/specs/seam-gate-block.v1.md` (not vendored) and pinned by
//! `conformance/gate_block_vector.json`. A seventh reading of the same text, linking none of the others.
//!
//! ```text
//! gate_body (v1) = u8(0x01) ‖ u8(status)
//!                ‖ F(attempt_id) ‖ F(domain) ‖ F(flow_id) ‖ F(env)
//!                ‖ be64(timeout_ms) ‖ u8(on_outage) ‖ be64(requested_at_ms)
//!   answered:    ‖ F(receipt_jcs) ‖ F(key_id) ‖ F(signature: 64 raw bytes) ‖ F(certificate_bytes)
//!   unavailable: ‖ u8(reason) ‖ be64(given_up_at_ms)
//! F(x) = be64(len(x)) ‖ x
//! gate_digest  = SHA-256( be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body )
//! ```
//!
//! **Reader only.** This crate decodes a Gate body and recomputes its digest. It never writes one, and it
//! does not verify the receipt's signature or the certificate (VG2–VG8 and the certificate check are
//! later waves): the block frames decision-api's bytes and never parses them.

use sha2::{Digest, Sha256};

/// The marker of the Gate trailer: after the selection `0x04`, before the governing `0x06`.
pub const GATE_TRAILER: u8 = 0x05;

/// The version byte leading the body. It is INSIDE the hashed body (unlike the `0x04` selection body's).
pub const GATE_BODY_V1: u8 = 0x01;

/// The Gate digest's domain tag (19 ASCII bytes).
pub const GATE_DIGEST_DOMAIN: &[u8] = b"seam-gate-digest:v1";

/// The raw Ed25519 signature length an answered body carries (never its base64url text).
pub const GATE_SIGNATURE_LEN: usize = 64;

/// The env rule shared by v6 field 12, the `0x06` body v2, the Gate body and the chain key: exactly the
/// bytes `sandbox` or `live`. Case-sensitive, untrimmed, a byte match and never a text decode, so the
/// empty string, `Live`, `live ` and non-UTF-8 bytes all fail.
pub fn is_flow_env(raw: &[u8]) -> bool {
    raw == b"sandbox" || raw == b"live"
}

/// Why a Gate body (or its trailer) is refused. Each refuses the whole commitment. The rule name is
/// advisory (spec §Refusal rules): only the refusal is normative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    BodyEmpty,
    UnknownVersion,
    StatusInvalid,
    OnOutageInvalid,
    ReasonReserved,
    ReasonInvalid,
    UnavailableUnderRefuseSeal,
    EnvNotSandboxOrLive,
    TextNotUtf8,
    TextEmpty,
    SignatureLength,
    BodyTruncated,
    BodyTrailingBytes,
}

impl GateRefusal {
    /// The spec's rule name.
    pub fn rule(self) -> &'static str {
        match self {
            Self::BodyEmpty => "gate_body_empty",
            Self::UnknownVersion => "gate_body_unknown_version",
            Self::StatusInvalid => "gate_status_invalid",
            Self::OnOutageInvalid => "gate_on_outage_invalid",
            Self::ReasonReserved => "gate_reason_reserved",
            Self::ReasonInvalid => "gate_reason_invalid",
            Self::UnavailableUnderRefuseSeal => "gate_unavailable_under_refuse_seal",
            Self::EnvNotSandboxOrLive => "env_not_sandbox_or_live",
            Self::TextNotUtf8 => "gate_text_not_utf8",
            Self::TextEmpty => "gate_text_empty",
            Self::SignatureLength => "gate_signature_length",
            Self::BodyTruncated => "gate_body_truncated",
            Self::BodyTrailingBytes => "gate_body_trailing_bytes",
        }
    }
}

impl std::fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Gate block refused: {}", self.rule())
    }
}

/// What the Gate call produced, as sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResult {
    /// `status = 1`: decision-api's signed answer, verbatim and unparsed.
    Answered {
        receipt_jcs: String,
        key_id: String,
        signature: [u8; GATE_SIGNATURE_LEN],
        /// `None` iff the frame is empty (decision-api's `certificate_jcs` was `null`: route).
        certificate_jcs: Option<String>,
    },
    /// `status = 2`: why Gate was unavailable (`1` timeout, `2` connect, `3` http_5xx, `5` circuit_open,
    /// `6` token_mint; `4` is reserved and refused).
    Unavailable { reason: u8, given_up_at_ms: u64 },
}

/// One decoded Gate body v1. The policy ranges (`timeout_ms` in `1..=2000`, VG7) are verifier checks of a
/// later wave, not decode rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateBlock {
    pub attempt_id: String,
    pub domain: String,
    pub flow_id: String,
    /// `sandbox` or `live`.
    pub env: String,
    pub timeout_ms: u64,
    /// `1` refuse_seal or `2` seal_gate_unavailable.
    pub on_outage: u8,
    pub requested_at_ms: u64,
    pub result: GateResult,
}

/// A strict reader: every overrun is [`GateRefusal::BodyTruncated`], never a panic. A `be64` frame length
/// is compared as a `u64` against what remains, so 2^64−1 refuses instead of wrapping.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], GateRefusal> {
        let rest = (self.b.len() - self.i) as u64;
        if n > rest {
            return Err(GateRefusal::BodyTruncated);
        }
        let out = &self.b[self.i..self.i + n as usize];
        self.i += n as usize;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, GateRefusal> {
        Ok(self.take(1)?[0])
    }
    fn be64(&mut self) -> Result<u64, GateRefusal> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }
    fn framed(&mut self) -> Result<&'a [u8], GateRefusal> {
        let n = self.be64()?;
        self.take(n)
    }
    /// A Gate text field: UTF-8 and non-empty.
    fn text(&mut self) -> Result<String, GateRefusal> {
        let s = std::str::from_utf8(self.framed()?).map_err(|_| GateRefusal::TextNotUtf8)?;
        if s.is_empty() {
            return Err(GateRefusal::TextEmpty);
        }
        Ok(s.to_owned())
    }
}

/// Decode a Gate body v1 (the trailer's body, version byte included). Strict: every body rule of the spec
/// refuses here and nothing may follow the last field. The binding to the commitment's env
/// (`gate_env_binding`) needs the `0x06` trailer and is applied by
/// [`crate::commitment::decode_commitment_trailers`].
pub fn decode_gate_body(body: &[u8]) -> Result<GateBlock, GateRefusal> {
    if body.is_empty() {
        return Err(GateRefusal::BodyEmpty);
    }
    let mut r = Reader { b: body, i: 0 };
    if r.u8()? != GATE_BODY_V1 {
        return Err(GateRefusal::UnknownVersion);
    }
    let status = r.u8()?;
    if status != 1 && status != 2 {
        return Err(GateRefusal::StatusInvalid);
    }
    let attempt_id = r.text()?;
    let domain = r.text()?;
    let flow_id = r.text()?;
    let env = r.framed()?;
    if !is_flow_env(env) {
        return Err(GateRefusal::EnvNotSandboxOrLive);
    }
    let env = String::from_utf8(env.to_vec()).expect("a flow env is ASCII");
    let timeout_ms = r.be64()?;
    let on_outage = r.u8()?;
    if on_outage != 1 && on_outage != 2 {
        return Err(GateRefusal::OnOutageInvalid);
    }
    let requested_at_ms = r.be64()?;
    let result = if status == 1 {
        let receipt_jcs = r.text()?;
        let key_id = r.text()?;
        let signature = <[u8; GATE_SIGNATURE_LEN]>::try_from(r.framed()?)
            .map_err(|_| GateRefusal::SignatureLength)?;
        let cert = r.framed()?;
        let certificate_jcs = if cert.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(cert)
                    .map_err(|_| GateRefusal::TextNotUtf8)?
                    .to_owned(),
            )
        };
        GateResult::Answered {
            receipt_jcs,
            key_id,
            signature,
            certificate_jcs,
        }
    } else {
        // An outage under `refuse_seal` is the typed GATE_UNAVAILABLE refusal: nothing is sealed, so
        // such a body can only be a forgery.
        if on_outage == 1 {
            return Err(GateRefusal::UnavailableUnderRefuseSeal);
        }
        let reason = r.u8()?;
        match reason {
            1 | 2 | 3 | 5 | 6 => {}
            4 => return Err(GateRefusal::ReasonReserved),
            _ => return Err(GateRefusal::ReasonInvalid),
        }
        GateResult::Unavailable {
            reason,
            given_up_at_ms: r.be64()?,
        }
    };
    if r.i != body.len() {
        return Err(GateRefusal::BodyTrailingBytes);
    }
    Ok(GateBlock {
        attempt_id,
        domain,
        flow_id,
        env,
        timeout_ms,
        on_outage,
        requested_at_ms,
        result,
    })
}

/// `seam-gate-digest:v1` over a Gate body, hashed WHOLE (its version byte included; the trailer's marker
/// and `u32le` length are not). It does not decode the body: a verifier decodes it first
/// ([`decode_gate_body`]) and frames field 10 only from this recomputation (VG1).
pub fn gate_digest(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((GATE_DIGEST_DOMAIN.len() as u64).to_be_bytes());
    h.update(GATE_DIGEST_DOMAIN);
    h.update(body);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 27-byte preimage prefix the spec pins: `be64(19) ‖ "seam-gate-digest:v1"`.
    #[test]
    fn the_domain_is_19_bytes_and_framed_be64() {
        assert_eq!(GATE_DIGEST_DOMAIN.len(), 19);
        let mut want = vec![0, 0, 0, 0, 0, 0, 0, 0x13];
        want.extend_from_slice(GATE_DIGEST_DOMAIN);
        let mut h = Sha256::new();
        h.update(&want);
        assert_eq!(<[u8; 32]>::from(h.finalize()), gate_digest(&[]));
    }

    #[test]
    fn the_env_rule_is_a_byte_match() {
        assert!(is_flow_env(b"sandbox") && is_flow_env(b"live"));
        for bad in [&b""[..], b"Live", b"live ", b"prod", b"SANDBOX", &[0xff]] {
            assert!(!is_flow_env(bad), "{bad:?}");
        }
    }

    /// A body of an unavailable outcome, built from the spec text alone, round-trips through the decoder;
    /// a frame length of 2^64−1 refuses as truncated rather than wrapping.
    #[test]
    fn an_unavailable_body_decodes_and_an_oversized_frame_refuses() {
        let f = |b: &mut Vec<u8>, x: &[u8]| {
            b.extend_from_slice(&(x.len() as u64).to_be_bytes());
            b.extend_from_slice(x);
        };
        let mut b = vec![1, 2];
        for t in [&b"a"[..], b"d", b"f", b"live"] {
            f(&mut b, t);
        }
        b.extend_from_slice(&800u64.to_be_bytes());
        b.push(2);
        b.extend_from_slice(&7u64.to_be_bytes());
        b.push(5);
        b.extend_from_slice(&9u64.to_be_bytes());
        let g = decode_gate_body(&b).unwrap();
        assert_eq!(g.env, "live");
        assert_eq!(
            g.result,
            GateResult::Unavailable {
                reason: 5,
                given_up_at_ms: 9
            }
        );
        let mut huge = vec![1, 2];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        huge.extend_from_slice(b"a");
        assert_eq!(decode_gate_body(&huge), Err(GateRefusal::BodyTruncated));
    }
}
