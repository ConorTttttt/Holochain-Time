//! Time statements signed by Holochain oracle agents.
//!
//! An oracle is an agent whose key a DNA lists as trusted for time. It answers
//! a nonce with a statement "the time is within [earliest, latest]", signed
//! with its agent key. Every field is a string, and the fields are declared in
//! alphabetical order, for one reason: the signed bytes are the MessagePack
//! encoding Holochain uses for any serializable value (`rmp_serde` with struct
//! maps). A Unyt Smart Agreement receives the same statement as JSON, and its
//! `hdi_verify_signature` helper re-encodes that JSON object with the same
//! encoder. JSON objects come back with sorted keys and string values encode
//! identically, so the bytes match and one signature serves both Holochain
//! validation and Unyt.
//!
//! Each oracle keeps one statement chain per network (DNA):
//!
//! - `dna` names the network whose cell signed it, so the chains an agent key
//!   keeps in different cells are never mistaken for a fork of one chain;
//! - `seq` increases by one and `prev` carries the hex of the previous
//!   signature;
//! - `floor` is the largest `earliest` signed before on this chain, and a
//!   statement's `latest` may never be below it.
//!
//! The floor makes every backwards step provable from at most two adjacent
//! statements (see [`crate::malfeasance`]), however gradually it is taken.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::{hex32, to_hex};
use crate::interval::{TimeInterval, MAX_ABS_MICROS};
use crate::keys::{agent_key_from_b64, dna_hash_from_b64};
use crate::verifier::Ed25519Verifier;

/// Domain string carried in every statement. v2 added `dna` and `floor`.
pub const STATEMENT_DOMAIN: &str = "hc-vtime/oracle-statement/v2";

/// The signed content. Field order is load-bearing: keep it alphabetical.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OracleTimeStatement {
    /// `DnaHashB64` of the network whose cell signed this statement.
    pub dna: String,
    /// Always [`STATEMENT_DOMAIN`].
    pub domain: String,
    /// Microseconds since the Unix epoch, canonical decimal.
    pub earliest: String,
    /// The largest `earliest` of any earlier statement on this chain,
    /// canonical decimal; "" exactly when `seq` is 0.
    pub floor: String,
    /// Microseconds since the Unix epoch, canonical decimal.
    pub latest: String,
    /// 64 lowercase hex characters: the 32-byte nonce the oracle answered.
    pub nonce: String,
    /// The oracle's `AgentPubKeyB64`.
    pub oracle: String,
    /// Lowercase hex of this oracle's previous statement signature, or "".
    pub prev: String,
    /// Canonical decimal sequence number, starting at 0.
    pub seq: String,
}

/// A statement plus the oracle's Ed25519 signature over its MessagePack bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedOracleStatement {
    /// What was signed.
    pub statement: OracleTimeStatement,
    /// 64-byte Ed25519 signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// A statement's position in its chain: what the oracle must put in `seq`,
/// `prev` and `floor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLink {
    /// Sequence number.
    pub seq: u64,
    /// Previous signature (None exactly at seq 0).
    pub prev: Option<[u8; 64]>,
    /// High-water mark of earlier `earliest` values (None exactly at seq 0).
    pub floor: Option<i64>,
}

impl ChainLink {
    /// The first statement of a chain.
    pub fn genesis() -> Self {
        Self {
            seq: 0,
            prev: None,
            floor: None,
        }
    }

    /// The link that follows `last` on the same chain.
    pub fn after(last: &SignedOracleStatement) -> Result<Self> {
        let p = last.statement.parse_fields()?;
        let prev: [u8; 64] = last
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("previous signature must be 64 bytes".into()))?;
        let floor = match p.floor {
            Some(f) => f.max(p.interval.earliest_us),
            None => p.interval.earliest_us,
        };
        let seq = p.seq.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Self {
            seq,
            prev: Some(prev),
            floor: Some(floor),
        })
    }
}

/// The parsed, canonical fields of a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStatement {
    /// The attested interval.
    pub interval: TimeInterval,
    /// The nonce answered.
    pub nonce: [u8; 32],
    /// Position in the chain.
    pub seq: u64,
    /// Previous signature, if any.
    pub prev: Option<[u8; 64]>,
    /// Chain high-water mark, if any.
    pub floor: Option<i64>,
}

/// The checked facts of a signed statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStatement {
    /// The oracle's raw Ed25519 key.
    pub oracle_key: [u8; 32],
    /// The `DnaHashB64` the statement names.
    pub dna: String,
    /// The attested interval.
    pub interval: TimeInterval,
    /// The nonce answered.
    pub nonce: [u8; 32],
    /// Position in the oracle's statement chain.
    pub seq: u64,
    /// Previous signature, if any.
    pub prev: Option<[u8; 64]>,
    /// Chain high-water mark, if any.
    pub floor: Option<i64>,
}

impl VerifiedStatement {
    /// True when the statement contradicts itself: it says the time is at
    /// most `latest`, yet its chain already proved the time reached `floor`.
    pub fn self_contradictory(&self) -> bool {
        matches!(self.floor, Some(f) if self.interval.latest_us < f)
    }
}

/// Parse a canonical decimal integer: optional '-', no '+', no leading zeros,
/// magnitude below 2^53. Canonical text means one value has one encoding.
pub fn parse_canonical_i64(s: &str, what: &str) -> Result<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !(digits.len() > 1 && digits.starts_with('0'))
        && !(s.starts_with('-') && digits == "0");
    if !canonical {
        return Err(Error::InvalidStatement(format!(
            "{what} is not a canonical decimal: {s:?}"
        )));
    }
    let v: i64 = s
        .parse()
        .map_err(|_| Error::InvalidStatement(format!("{what} out of range")))?;
    // unsigned_abs: i64::MIN.abs() would overflow.
    if v.unsigned_abs() >= MAX_ABS_MICROS as u64 {
        return Err(Error::InvalidStatement(format!("{what} exceeds 2^53")));
    }
    Ok(v)
}

impl OracleTimeStatement {
    /// Build a statement for `interval` answering `nonce`, at `link` in the
    /// chain the oracle keeps in network `dna_b64`.
    pub fn new(
        oracle_b64: String,
        dna_b64: String,
        nonce: &[u8; 32],
        interval: TimeInterval,
        link: ChainLink,
    ) -> Self {
        Self {
            dna: dna_b64,
            domain: STATEMENT_DOMAIN.to_string(),
            earliest: interval.earliest_us.to_string(),
            floor: link.floor.map(|f| f.to_string()).unwrap_or_default(),
            latest: interval.latest_us.to_string(),
            nonce: to_hex(nonce),
            oracle: oracle_b64,
            prev: link.prev.map(|s| to_hex(&s)).unwrap_or_default(),
            seq: link.seq.to_string(),
        }
    }

    /// The exact bytes an oracle signs: Holochain's MessagePack encoding
    /// (`holochain_serialized_bytes::encode`, i.e. rmp-serde with struct maps).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut se = rmp_serde::encode::Serializer::new(Vec::with_capacity(320)).with_struct_map();
        self.serialize(&mut se)
            .map_err(|e| Error::Malformed(format!("statement encoding failed: {e}")))?;
        Ok(se.into_inner())
    }

    /// Check every field is canonical and return the parsed values, without
    /// judging whether the statement contradicts its own floor. Malfeasance
    /// proofs use this; evidence uses [`Self::parse`].
    pub fn parse_fields(&self) -> Result<ParsedStatement> {
        if self.domain != STATEMENT_DOMAIN {
            return Err(Error::InvalidStatement(format!(
                "unexpected domain {:?}",
                self.domain
            )));
        }
        dna_hash_from_b64(&self.dna)
            .map_err(|_| Error::InvalidStatement("dna must be a DnaHashB64".into()))?;
        let earliest = parse_canonical_i64(&self.earliest, "earliest")?;
        let latest = parse_canonical_i64(&self.latest, "latest")?;
        let interval = TimeInterval::new(earliest, latest)?;
        let nonce = hex32(&self.nonce).map_err(|_| {
            Error::InvalidStatement("nonce must be 64 lowercase hex characters".into())
        })?;
        let seq = parse_canonical_i64(&self.seq, "seq")?;
        if seq < 0 {
            return Err(Error::InvalidStatement("seq must not be negative".into()));
        }
        let prev =
            if self.prev.is_empty() {
                None
            } else {
                let bytes = crate::hash::from_hex(&self.prev)
                    .map_err(|_| Error::InvalidStatement("prev must be lowercase hex".into()))?;
                Some(bytes.try_into().map_err(|_| {
                    Error::InvalidStatement("prev must be a 64-byte signature".into())
                })?)
            };
        let floor = if self.floor.is_empty() {
            None
        } else {
            Some(parse_canonical_i64(&self.floor, "floor")?)
        };
        let genesis = seq == 0;
        if genesis == prev.is_some() || genesis == floor.is_some() {
            return Err(Error::InvalidStatement(
                "prev and floor must be empty exactly when seq is 0".into(),
            ));
        }
        Ok(ParsedStatement {
            interval,
            nonce,
            seq: seq as u64,
            prev,
            floor,
        })
    }

    /// [`Self::parse_fields`], and reject a statement whose `latest` is below
    /// its own `floor`: such a statement is a confession, not evidence.
    pub fn parse(&self) -> Result<ParsedStatement> {
        let p = self.parse_fields()?;
        if let Some(floor) = p.floor {
            if p.interval.latest_us < floor {
                return Err(Error::InvalidStatement(
                    "latest is below the chain's floor".into(),
                ));
            }
        }
        Ok(p)
    }
}

fn verify_with(
    signed: &SignedOracleStatement,
    parsed: ParsedStatement,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedStatement> {
    let oracle_key = agent_key_from_b64(&signed.statement.oracle)?;
    let sig: &[u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("oracle signature must be 64 bytes".into()))?;
    if !verifier.verify(&oracle_key, &signed.statement.signing_bytes()?, sig)? {
        return Err(Error::BadSignature("oracle statement signature"));
    }
    Ok(VerifiedStatement {
        oracle_key,
        dna: signed.statement.dna.clone(),
        interval: parsed.interval,
        nonce: parsed.nonce,
        seq: parsed.seq,
        prev: parsed.prev,
        floor: parsed.floor,
    })
}

/// Verify a signed statement's form and signature for use as evidence (not
/// whether the oracle or network is trusted; that is policy, see
/// [`crate::evidence`]).
pub fn verify_signed_statement(
    signed: &SignedOracleStatement,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedStatement> {
    let parsed = signed.statement.parse()?;
    verify_with(signed, parsed, verifier)
}

/// Verify a signed statement's form and signature as possible evidence of
/// misbehaviour: a statement below its own floor is accepted here.
pub fn verify_signed_statement_for_proof(
    signed: &SignedOracleStatement,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedStatement> {
    let parsed = signed.statement.parse_fields()?;
    verify_with(signed, parsed, verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{agent_key_to_b64, dna_hash_to_b64};

    fn sample() -> OracleTimeStatement {
        OracleTimeStatement::new(
            agent_key_to_b64(&[3; 32]),
            dna_hash_to_b64(&[5; 32]),
            &[0xab; 32],
            TimeInterval::new(1_793_000_000_000_000, 1_793_000_002_000_000).unwrap(),
            ChainLink::genesis(),
        )
    }

    #[test]
    fn canonical_decimal() {
        assert_eq!(parse_canonical_i64("0", "x").unwrap(), 0);
        assert_eq!(parse_canonical_i64("-5", "x").unwrap(), -5);
        for bad in [
            "",
            "-",
            "+1",
            "01",
            "-0",
            "1.0",
            " 1",
            "1e3",
            "9007199254740992",
        ] {
            assert!(parse_canonical_i64(bad, "x").is_err(), "{bad:?} accepted");
        }
    }

    /// Regression (review P3, arithmetic): i64::MIN and i64::MAX are rejected
    /// in debug and release builds alike (the baseline panicked in debug and
    /// accepted i64::MIN in release).
    #[test]
    fn extreme_decimals_are_rejected_without_panicking() {
        for s in [
            "-9223372036854775808",
            "9223372036854775807",
            "-9007199254740992",
            "92233720368547758080",
        ] {
            assert!(parse_canonical_i64(s, "x").is_err(), "{s} accepted");
        }
        assert_eq!(
            parse_canonical_i64("-9007199254740991", "x").unwrap(),
            -9_007_199_254_740_991
        );
    }

    /// The property the Unyt integration depends on: encoding the struct and
    /// encoding the equivalent JSON object give identical bytes.
    #[test]
    fn struct_and_json_object_encode_identically() {
        let mut st = sample();
        st.seq = "4".into();
        st.prev = to_hex(&[7u8; 64]);
        st.floor = "1792999999000000".into();
        // serde_json maps iterate in sorted key order, so byte equality also
        // proves the struct's fields are declared alphabetically.
        let json = serde_json::to_value(&st).unwrap();
        let mut se = rmp_serde::encode::Serializer::new(Vec::new()).with_struct_map();
        json.serialize(&mut se).unwrap();
        assert_eq!(st.signing_bytes().unwrap(), se.into_inner());
    }

    #[test]
    fn rejects_prev_seq_floor_mismatch() {
        let mut st = sample();
        st.seq = "1".into();
        assert!(st.parse().is_err(), "seq 1 needs prev and floor");
        st.prev = to_hex(&[7u8; 64]);
        assert!(st.parse().is_err(), "seq 1 needs a floor");
        st.floor = "1".into();
        assert!(st.parse().is_ok());
        st.seq = "0".into();
        assert!(st.parse().is_err(), "seq 0 must not have prev or floor");
    }

    #[test]
    fn rejects_bad_dna_and_old_domain() {
        let mut st = sample();
        st.dna = agent_key_to_b64(&[5; 32]);
        assert!(st.parse().is_err(), "an agent key is not a DNA hash");
        let mut st = sample();
        st.domain = "hc-vtime/oracle-statement/v1".into();
        assert!(st.parse().is_err());
    }

    #[test]
    fn floor_rules() {
        let mut st = sample();
        st.seq = "1".into();
        st.prev = to_hex(&[7u8; 64]);
        st.floor = "1793000002000001".into(); // one microsecond above latest
        assert!(
            st.parse().is_err(),
            "a statement below its floor is not evidence"
        );
        assert!(st.parse_fields().is_ok(), "but it parses as a proof");
        st.floor = "1793000002000000".into(); // equal to latest
        assert!(st.parse().is_ok());
    }

    #[test]
    fn chain_link_carries_the_high_water_mark() {
        let mut first = SignedOracleStatement {
            statement: sample(),
            signature: alloc::vec![9; 64],
        };
        let link = ChainLink::after(&first).unwrap();
        assert_eq!(
            link,
            ChainLink {
                seq: 1,
                prev: Some([9; 64]),
                floor: Some(1_793_000_000_000_000)
            }
        );

        // A later statement whose earliest is lower keeps the old floor.
        first.statement = OracleTimeStatement::new(
            first.statement.oracle.clone(),
            first.statement.dna.clone(),
            &[1; 32],
            TimeInterval::new(1_792_999_999_000_000, 1_793_000_001_000_000).unwrap(),
            link,
        );
        let next = ChainLink::after(&first).unwrap();
        assert_eq!(next.floor, Some(1_793_000_000_000_000));
        assert_eq!(next.seq, 2);
    }
}
