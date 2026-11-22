//! The chain key and its genesis (`chain_bundle` v1), written from `seam-event.v1.md` §Chain key and
//! genesis and pinned by `conformance/chain/chain_genesis_vectors.json` and `chain_link_vectors.json`
//! (copied byte for byte from seam-runtime `fixtures/chain/`).
//!
//! ```text
//! ChainKey   = (kind, stream_id, tenant, flow_id, env)
//!              kind 0 = cell   : tenant = flow_id = env = ""
//!              kind 1 = tenant : tenant ≠ "", flow_id = env = ""
//!              kind 2 = flow   : tenant ≠ "", flow_id ≠ "", env ∈ {"sandbox", "live"}
//! P(x)       = u32le(len(x)) ‖ x
//! genesis(K) = SHA-256( P("seam.audit.chain-genesis.v1") ‖ P([kind]) ‖ P(stream_id) ‖ P(tenant)
//!                       ‖ P(flow_id) ‖ P(env) )
//! ```
//!
//! **Reader scope (RTC C4, W2).** A chained event that carries tag 29 is keyed by its `ChainKey` and its
//! chain's first link must be `genesis(K)`; one without tag 29 stays on the legacy per-tenant rule with
//! the zero genesis. The fuller V-checks (V14 env vs the v6 seal, attestation v3, the flows list) are W5.

use sha2::{Digest, Sha256};

/// The genesis preimage's domain part.
pub const CHAIN_GENESIS_DOMAIN: &[u8] = b"seam.audit.chain-genesis.v1";

/// One chain's identity. Construct it with [`ChainKey::new`], which refuses a key outside the table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainKey {
    /// `0` cell, `1` tenant, `2` flow.
    pub kind: u8,
    pub stream_id: String,
    pub tenant: String,
    pub flow_id: String,
    pub env: String,
}

/// The spec's delivery-stream rule: `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`.
pub fn is_valid_stream_id(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= 32
        && alnum(&b[0])
        && alnum(&b[b.len() - 1])
        && b.iter().all(|c| alnum(c) || *c == b'-')
}

impl ChainKey {
    /// Build a key, refusing one outside the table before anything is hashed. The error is the spec's
    /// rule name (`unknown_kind`, `stream_id_invalid`, `cell_key_not_empty`, `tenant_empty`,
    /// `tenant_key_has_flow`, `flow_id_empty`, `env_not_sandbox_or_live`); advisory, like every rule name.
    pub fn new(
        kind: u32,
        stream_id: &str,
        tenant: &str,
        flow_id: &str,
        env: &str,
    ) -> Result<Self, &'static str> {
        if kind > 2 {
            return Err("unknown_kind");
        }
        if !is_valid_stream_id(stream_id) {
            return Err("stream_id_invalid");
        }
        match kind {
            0 if !(tenant.is_empty() && flow_id.is_empty() && env.is_empty()) => {
                return Err("cell_key_not_empty")
            }
            1 | 2 if tenant.is_empty() => return Err("tenant_empty"),
            1 if !(flow_id.is_empty() && env.is_empty()) => return Err("tenant_key_has_flow"),
            2 if flow_id.is_empty() => return Err("flow_id_empty"),
            2 if !crate::gate::is_flow_env(env.as_bytes()) => {
                return Err("env_not_sandbox_or_live")
            }
            _ => {}
        }
        Ok(Self {
            kind: kind as u8,
            stream_id: stream_id.into(),
            tenant: tenant.into(),
            flow_id: flow_id.into(),
            env: env.into(),
        })
    }

    /// The genesis preimage (every part framed, an empty part is four zero bytes, never omitted).
    pub fn genesis_preimage(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for part in [
            CHAIN_GENESIS_DOMAIN,
            &[self.kind],
            self.stream_id.as_bytes(),
            self.tenant.as_bytes(),
            self.flow_id.as_bytes(),
            self.env.as_bytes(),
        ] {
            v.extend_from_slice(&(part.len() as u32).to_le_bytes());
            v.extend_from_slice(part);
        }
        v
    }

    /// `genesis(K)`: the `prev_checksum` of this chain's first entry. Never 32 zero bytes.
    pub fn genesis(&self) -> [u8; 32] {
        Sha256::digest(self.genesis_preimage()).into()
    }
}

impl std::fmt::Display for ChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let kind = match self.kind {
            0 => "cell",
            1 => "tenant",
            _ => "flow",
        };
        write!(
            f,
            "{kind}(stream {:?}, tenant {:?}, flow {:?}, env {:?})",
            self.stream_id, self.tenant, self.flow_id, self.env
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's framing note: every preimage starts `1b 00 00 00 ‖ "seam.audit.chain-genesis.v1"`, and
    /// the kind byte is framed `01 00 00 00 ‖ kind`. The vector's `cell` genesis, inlined so a packaged
    /// crate tests it.
    #[test]
    fn the_cell_genesis_matches_the_vector() {
        let k = ChainKey::new(0, "cell-a", "", "", "").unwrap();
        let p = k.genesis_preimage();
        assert_eq!(&p[..4], &[0x1b, 0, 0, 0]);
        assert_eq!(&p[31..36], &[1, 0, 0, 0, 0]);
        assert_eq!(
            crate::verify::hex(&k.genesis()),
            "c41ce6adcb017bd5dc8378fc47acadd94f1ddc40e9df779e6842ef1160e0e6f2"
        );
    }

    #[test]
    fn keys_outside_the_table_refuse() {
        assert_eq!(ChainKey::new(3, "a", "t", "", ""), Err("unknown_kind"));
        assert_eq!(ChainKey::new(1, "A", "t", "", ""), Err("stream_id_invalid"));
        assert_eq!(
            ChainKey::new(1, "a-", "t", "", ""),
            Err("stream_id_invalid")
        );
        assert_eq!(
            ChainKey::new(0, "a", "t", "", ""),
            Err("cell_key_not_empty")
        );
        assert_eq!(
            ChainKey::new(2, "a", "t", "f", "prod"),
            Err("env_not_sandbox_or_live")
        );
        assert!(ChainKey::new(2, "a", "t", "f", "live").is_ok());
    }
}
