//! The chain key and its genesis (`chain_bundle` v2), written from `seam-event.v1.md` §Chain key and
//! genesis and pinned by `conformance/chain/chain_genesis_vectors.json` and `chain_link_vectors.json`
//! (copied byte for byte from seam-runtime `fixtures/chain/`).
//!
//! ```text
//! ChainKey   = (kind, stream_id, tenant, flow_id, env, version)
//!              kind 0 = cell   : tenant = flow_id = env = "", version = 0
//!              kind 1 = tenant : tenant ≠ "", flow_id = env = "", version = 0
//!              kind 2 = flow   : tenant ≠ "", flow_id ≠ "", env = "live" with version = 0,
//!                                or env = "sandbox" with version ≥ 1
//! P(x)       = u32le(len(x)) ‖ x
//! V          = P("") when version = 0 (the absent form), else P(u32le(version))
//! genesis(K) = SHA-256( P("seam.audit.chain-genesis.v2") ‖ P([kind]) ‖ P(stream_id) ‖ P(tenant)
//!                       ‖ P(flow_id) ‖ P(env) ‖ V )
//! ```
//!
//! **Reader scope (RTC C4, W2).** A chained event that carries tag 29 is keyed by its `ChainKey` and its
//! chain's first link must be `genesis(K)`; one without tag 29 stays on the legacy per-tenant rule with
//! the zero genesis. The fuller V-checks (V14 env vs the v6 seal, attestation v3, the flows list) are W5.

use sha2::{Digest, Sha256};

/// The genesis preimage's domain part.
pub const CHAIN_GENESIS_DOMAIN: &[u8] = b"seam.audit.chain-genesis.v2";

/// One chain's identity. Construct it with [`ChainKey::new`], which refuses a key outside the table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainKey {
    /// `0` cell, `1` tenant, `2` flow.
    pub kind: u8,
    pub stream_id: String,
    pub tenant: String,
    pub flow_id: String,
    pub env: String,
    /// The CP flow version: `≥ 1` exactly on a sandbox flow key, `0` (absent) everywhere else.
    pub version: u32,
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
    /// `tenant_key_has_flow`, `flow_id_empty`, `env_not_sandbox_or_live`, `live_key_has_version`,
    /// `sandbox_version_missing`); advisory, like every rule name. A version on a cell or tenant key is
    /// `cell_key_not_empty` / `tenant_key_has_flow`.
    pub fn new(
        kind: u32,
        stream_id: &str,
        tenant: &str,
        flow_id: &str,
        env: &str,
        version: u32,
    ) -> Result<Self, &'static str> {
        if kind > 2 {
            return Err("unknown_kind");
        }
        if !is_valid_stream_id(stream_id) {
            return Err("stream_id_invalid");
        }
        match kind {
            0 if !(tenant.is_empty() && flow_id.is_empty() && env.is_empty() && version == 0) => {
                return Err("cell_key_not_empty")
            }
            1 | 2 if tenant.is_empty() => return Err("tenant_empty"),
            1 if !(flow_id.is_empty() && env.is_empty() && version == 0) => {
                return Err("tenant_key_has_flow")
            }
            2 if flow_id.is_empty() => return Err("flow_id_empty"),
            2 if !crate::gate::is_flow_env(env.as_bytes()) => {
                return Err("env_not_sandbox_or_live")
            }
            2 if env == "live" && version != 0 => return Err("live_key_has_version"),
            2 if env == "sandbox" && version == 0 => return Err("sandbox_version_missing"),
            _ => {}
        }
        Ok(Self {
            kind: kind as u8,
            stream_id: stream_id.into(),
            tenant: tenant.into(),
            flow_id: flow_id.into(),
            env: env.into(),
            version,
        })
    }

    /// The genesis preimage (every part framed, an empty part is four zero bytes, never omitted). The
    /// version part is framed last: `P("")` for version 0, `P(u32le(version))` otherwise.
    pub fn genesis_preimage(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let ver = self.version.to_le_bytes();
        let ver: &[u8] = if self.version == 0 { &[] } else { &ver };
        for part in [
            CHAIN_GENESIS_DOMAIN,
            &[self.kind],
            self.stream_id.as_bytes(),
            self.tenant.as_bytes(),
            self.flow_id.as_bytes(),
            self.env.as_bytes(),
            ver,
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
            "{kind}(stream {:?}, tenant {:?}, flow {:?}, env {:?}, version {})",
            self.stream_id, self.tenant, self.flow_id, self.env, self.version
        )
    }
}

/// One chain of a stream, named on the command line (`seam-verify chain --chain <SELECTOR>`) so a stream
/// holding several chains can be verified one chain at a time (Flows W5, D5: a Live chain and a Sandbox
/// version chain of the same flow each verify alone).
///
/// Grammar (no stream id: a stream file is one delivery stream, and a selection spanning two is refused by
/// the caller):
///
/// ```text
/// cell
/// tenant:<tenant>
/// flow:<tenant>:<flow_id>:live
/// flow:<tenant>:<flow_id>:sandbox:<version>
/// ```
///
/// The tenant may not contain `:`; the flow id may (env and version are read from the right). The shape is
/// checked with the chain-key table ([`ChainKey::new`]), so a selector that names no chain (a Live version,
/// a Sandbox without one) is refused with that table's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSelector {
    pub kind: u8,
    pub tenant: String,
    pub flow_id: String,
    pub env: String,
    pub version: u32,
}

impl ChainSelector {
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = |why: &str| {
            format!(
                "--chain {s:?}: {why} (want cell | tenant:<tenant> | flow:<tenant>:<flow_id>:live | \
                 flow:<tenant>:<flow_id>:sandbox:<version>)"
            )
        };
        let (kind, tenant, flow_id, env, version) = if s == "cell" {
            (0, "", "", "", 0)
        } else if let Some(t) = s.strip_prefix("tenant:") {
            if t.contains(':') {
                return Err(bad("a tenant may not contain ':'"));
            }
            (1, t, "", "", 0)
        } else if let Some(rest) = s.strip_prefix("flow:") {
            let (tenant, rest) = rest.split_once(':').ok_or_else(|| bad("no flow id"))?;
            let (flow_id, env, version) = if let Some(f) = rest.strip_suffix(":live") {
                (f, "live", 0)
            } else {
                let (head, ver) = rest.rsplit_once(':').ok_or_else(|| bad("no env"))?;
                let f = head
                    .strip_suffix(":sandbox")
                    .ok_or_else(|| bad("env must be live, or sandbox:<version>"))?;
                let v: u32 = ver
                    .parse()
                    .ok()
                    .filter(|_| {
                        ver.bytes().all(|b| b.is_ascii_digit())
                            && !(ver.len() > 1 && ver.starts_with('0'))
                    })
                    .ok_or_else(|| bad("a sandbox version is a decimal u32"))?;
                (f, "sandbox", v)
            };
            (2, tenant, flow_id, env, version)
        } else {
            return Err(bad("unknown chain kind"));
        };
        // The stream id is not part of a selector; any valid one checks the rest of the key's shape.
        ChainKey::new(kind, "x", tenant, flow_id, env, version).map_err(bad)?;
        Ok(Self {
            kind: kind as u8,
            tenant: tenant.into(),
            flow_id: flow_id.into(),
            env: env.into(),
            version,
        })
    }

    /// Whether `key` is this selector's chain, in any stream.
    pub fn matches(&self, key: &ChainKey) -> bool {
        key.kind == self.kind
            && key.tenant == self.tenant
            && key.flow_id == self.flow_id
            && key.env == self.env
            && key.version == self.version
    }
}

impl std::fmt::Display for ChainSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match (self.kind, self.env.as_str()) {
            (0, _) => write!(f, "cell"),
            (1, _) => write!(f, "tenant:{}", self.tenant),
            (_, "live") => write!(f, "flow:{}:{}:live", self.tenant, self.flow_id),
            _ => write!(
                f,
                "flow:{}:{}:sandbox:{}",
                self.tenant, self.flow_id, self.version
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing: every preimage starts `1b 00 00 00 ‖ "seam.audit.chain-genesis.v2"`, the kind byte is
    /// framed `01 00 00 00 ‖ kind`, and the version part is last. The vector's `cell` and
    /// `flow_sandbox_v1` geneses, inlined so a packaged crate tests them.
    #[test]
    fn the_geneses_match_the_vector() {
        let k = ChainKey::new(0, "cell-a", "", "", "", 0).unwrap();
        let p = k.genesis_preimage();
        assert_eq!(&p[..4], &[0x1b, 0, 0, 0]);
        assert_eq!(&p[31..36], &[1, 0, 0, 0, 0]);
        assert_eq!(
            &p[p.len() - 4..],
            &[0, 0, 0, 0],
            "V = P(\"\") for version 0"
        );
        assert_eq!(
            crate::verify::hex(&k.genesis()),
            "58336694b00675fba6de5bfd9cd0fc36e135e3b6761342efb2316e768783188d"
        );
        let s = ChainKey::new(2, "cell-a", "acme", "flow-fraud", "sandbox", 1).unwrap();
        assert_eq!(
            &s.genesis_preimage()[s.genesis_preimage().len() - 8..],
            &[4, 0, 0, 0, 1, 0, 0, 0],
            "V = P(u32le(1))"
        );
        assert_eq!(
            crate::verify::hex(&s.genesis()),
            "c0b1b2f3518f17f70b91e2e506be3137bdd495620b10c1354dcef241d3b2d596"
        );
    }

    #[test]
    fn keys_outside_the_table_refuse() {
        let k = ChainKey::new;
        assert_eq!(k(3, "a", "t", "", "", 0), Err("unknown_kind"));
        assert_eq!(k(1, "A", "t", "", "", 0), Err("stream_id_invalid"));
        assert_eq!(k(1, "a-", "t", "", "", 0), Err("stream_id_invalid"));
        assert_eq!(k(0, "a", "t", "", "", 0), Err("cell_key_not_empty"));
        assert_eq!(k(0, "a", "", "", "", 1), Err("cell_key_not_empty"));
        assert_eq!(k(1, "a", "t", "", "", 1), Err("tenant_key_has_flow"));
        assert_eq!(
            k(2, "a", "t", "f", "prod", 0),
            Err("env_not_sandbox_or_live")
        );
        assert_eq!(k(2, "a", "t", "f", "live", 1), Err("live_key_has_version"));
        assert_eq!(
            k(2, "a", "t", "f", "sandbox", 0),
            Err("sandbox_version_missing")
        );
        assert!(k(2, "a", "t", "f", "live", 0).is_ok());
        assert!(k(2, "a", "t", "f", "sandbox", 7).is_ok());
    }

    #[test]
    fn a_selector_parses_names_one_chain_and_refuses_what_names_none() {
        let live = ChainSelector::parse("flow:acme:flow-fraud:live").unwrap();
        let sb1 = ChainSelector::parse("flow:acme:flow-fraud:sandbox:1").unwrap();
        let k_live = ChainKey::new(2, "cell-a", "acme", "flow-fraud", "live", 0).unwrap();
        let k_sb1 = ChainKey::new(2, "cell-a", "acme", "flow-fraud", "sandbox", 1).unwrap();
        let k_sb2 = ChainKey::new(2, "cell-a", "acme", "flow-fraud", "sandbox", 2).unwrap();
        assert!(live.matches(&k_live) && !live.matches(&k_sb1));
        assert!(sb1.matches(&k_sb1) && !sb1.matches(&k_sb2) && !sb1.matches(&k_live));
        assert_eq!(live.to_string(), "flow:acme:flow-fraud:live");
        assert_eq!(sb1.to_string(), "flow:acme:flow-fraud:sandbox:1");
        let colon = ChainSelector::parse("flow:acme:a:b:sandbox:7").unwrap();
        assert_eq!((colon.flow_id.as_str(), colon.version), ("a:b", 7));
        assert_eq!(ChainSelector::parse("cell").unwrap().kind, 0);
        let t = ChainSelector::parse("tenant:acme").unwrap();
        assert!(t.matches(&ChainKey::new(1, "s", "acme", "", "", 0).unwrap()));
        for (bad, why) in [
            ("flow:acme:f:live:3", "env must be"),
            ("flow:acme:f:sandbox:0", "sandbox_version_missing"),
            ("flow:acme:f:sandbox:x", "decimal"),
            ("flow:acme:f:sandbox:+1", "decimal"),
            ("flow:acme:f:sandbox:007", "decimal"),
            ("flow:acme:f:staging", "env must be"),
            ("flow:acme:f", "no env"),
            ("flow::f:live", "tenant_empty"),
            ("flow:acme::live", "flow_id_empty"),
            ("tenant:", "tenant_empty"),
            ("tenant:a:b", "may not contain"),
            ("system", "unknown chain kind"),
        ] {
            let e = ChainSelector::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }
}
