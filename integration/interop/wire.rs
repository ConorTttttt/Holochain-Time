//! Proposed test-only v1 evidence-envelope codec (NOT a deployed zome format).
//! Only wraps bytes and strings; existing vtime_core performs ALL trust and
//! cryptographic verification. Canonical signing bytes remain unchanged.
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use vtime_core::evidence::{verify_evidence_set, MAX_EVIDENCE_ITEMS};
use vtime_core::roughtime::{MAX_REQUEST_PACKET_SIZE, MAX_RESPONSE_PACKET_SIZE};
use vtime_core::{
    Ed25519Verifier, OracleTimeStatement, RoughtimeEvidence, SignedOracleStatement,
    SourcedInterval, TimeEvidence, TimePolicy,
};

pub const FORMAT: &str = "hc-vtime/evidence-envelope";
pub const VERSION: u16 = 1;
/// Largest allowed fully encoded envelope, checked before MessagePack decoding.
pub const MAX_WIRE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub version: u16,
    pub items: Vec<WireItem>,
}

/// Exactly one kind and its payload may be present. The absent field must
/// be omitted from serialization, not represented as null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireItem {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roughtime: Option<WireRoughtime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<WireOracle>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRoughtime {
    pub server_public_key: ByteBuf,
    pub request: ByteBuf,
    pub response: ByteBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireOracle {
    pub statement: WireStatement,
    pub signature: ByteBuf,
}

/// Field order intentionally matches vtime_core::OracleTimeStatement exactly;
/// altering this order would change the Ed25519 signing bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireStatement {
    pub dna: String,
    pub domain: String,
    pub earliest: String,
    pub floor: String,
    pub latest: String,
    pub nonce: String,
    pub oracle: String,
    pub prev: String,
    pub seq: String,
}

impl From<OracleTimeStatement> for WireStatement {
    fn from(s: OracleTimeStatement) -> Self {
        Self {
            dna: s.dna,
            domain: s.domain,
            earliest: s.earliest,
            floor: s.floor,
            latest: s.latest,
            nonce: s.nonce,
            oracle: s.oracle,
            prev: s.prev,
            seq: s.seq,
        }
    }
}

impl From<WireStatement> for OracleTimeStatement {
    fn from(s: WireStatement) -> Self {
        Self {
            dna: s.dna,
            domain: s.domain,
            earliest: s.earliest,
            floor: s.floor,
            latest: s.latest,
            nonce: s.nonce,
            oracle: s.oracle,
            prev: s.prev,
            seq: s.seq,
        }
    }
}

impl Envelope {
    /// Adapt already-typed core evidence into a proposed versioned wire value.
    /// Signatures and Roughtime packet bytes are preserved verbatim.
    pub fn from_core(evidence: &[TimeEvidence]) -> Result<Self, String> {
        let items = evidence
            .iter()
            .map(|e| match e {
                TimeEvidence::Roughtime(v) => WireItem {
                    kind: "roughtime".into(),
                    roughtime: Some(WireRoughtime {
                        server_public_key: ByteBuf::from(v.server_public_key.clone()),
                        request: ByteBuf::from(v.request.clone()),
                        response: ByteBuf::from(v.response.clone()),
                    }),
                    oracle: None,
                },
                TimeEvidence::Oracle(v) => WireItem {
                    kind: "oracle".into(),
                    roughtime: None,
                    oracle: Some(WireOracle {
                        statement: WireStatement::from(v.statement.clone()),
                        signature: ByteBuf::from(v.signature.clone()),
                    }),
                },
            })
            .collect();
        let env = Self {
            format: FORMAT.into(),
            version: VERSION,
            items,
        };
        env.check_shape()?;
        Ok(env)
    }

    fn check_shape(&self) -> Result<(), String> {
        if self.format != FORMAT {
            return Err("unknown evidence envelope format".into());
        }
        if self.version != VERSION {
            return Err(format!(
                "unsupported evidence envelope version {}",
                self.version
            ));
        }
        if self.items.len() > MAX_EVIDENCE_ITEMS {
            return Err("too many evidence items in envelope".into());
        }
        for (index, item) in self.items.iter().enumerate() {
            match (item.kind.as_str(), &item.roughtime, &item.oracle) {
                ("roughtime", Some(rt), None) => {
                    if rt.server_public_key.len() != 32
                        || rt.request.len() > MAX_REQUEST_PACKET_SIZE
                        || rt.response.len() > MAX_RESPONSE_PACKET_SIZE
                    {
                        return Err(format!("Roughtime size bound failed at item {index}"));
                    }
                }
                ("oracle", None, Some(oracle)) => {
                    if oracle.signature.len() != 64 {
                        return Err(format!("oracle signature length failed at item {index}"));
                    }
                    let statement: OracleTimeStatement = oracle.statement.clone().into();
                    statement.parse().map_err(|e| {
                        format!("noncanonical oracle statement at item {index}: {e}")
                    })?;
                }
                _ => {
                    return Err(format!(
                        "unknown or inconsistent evidence kind at item {index}"
                    ))
                }
            }
        }
        Ok(())
    }

    /// Encode deterministically as a MessagePack *struct-map* with binary
    /// fields, never a MessagePack array or JSON text. Re-encoding a decoded
    /// value gives exactly these bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.check_shape()?;
        let bytes = rmp_serde::to_vec_named(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err("evidence envelope exceeds byte budget".into());
        }
        Ok(bytes)
    }

    /// A strict, complete parser. Denies unknown keys at every map level,
    /// unsupported versions and alternative MessagePack spellings.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err("evidence envelope exceeds byte budget".into());
        }
        let envelope: Self = rmp_serde::from_slice(bytes)
            .map_err(|e| format!("malformed evidence envelope: {e}"))?;
        let reencoded = envelope.encode()?;
        if reencoded != bytes {
            return Err("noncanonical MessagePack evidence envelope".into());
        }
        Ok(envelope)
    }

    pub fn into_core(self) -> Result<Vec<TimeEvidence>, String> {
        self.check_shape()?;
        self.items
            .into_iter()
            .map(
                |item| match (item.kind.as_str(), item.roughtime, item.oracle) {
                    ("roughtime", Some(rt), None) => {
                        Ok(TimeEvidence::Roughtime(RoughtimeEvidence {
                            server_public_key: rt.server_public_key.into_vec(),
                            request: rt.request.into_vec(),
                            response: rt.response.into_vec(),
                        }))
                    }
                    ("oracle", None, Some(oracle)) => {
                        Ok(TimeEvidence::Oracle(SignedOracleStatement {
                            statement: oracle.statement.into(),
                            signature: oracle.signature.into_vec(),
                        }))
                    }
                    _ => Err("invalid evidence kind".into()),
                },
            )
            .collect()
    }

    /// Compare with direct-core validation using the *same* policy and nonce.
    pub fn verify(
        bytes: &[u8],
        policy: &TimePolicy,
        verifier: &dyn Ed25519Verifier,
        expected_nonce: Option<&[u8; 32]>,
    ) -> Result<Vec<SourcedInterval>, String> {
        let items = Self::decode(bytes)?.into_core()?;
        verify_evidence_set(&items, policy, verifier, expected_nonce).map_err(|e| e.to_string())
    }
}
