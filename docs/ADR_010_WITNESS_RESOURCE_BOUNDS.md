# Witness ancestry and entry identity hardening

During sprint consolidation, review found that limiting the number of supplied
anchors did not bound the length of each source-chain activity request. The
coordinator now rejects anchors more than 255 actions behind the target and
uses an explicit take limit of at most 256 actions. Failure to obtain the
required ancestry still rejects the call. A recent anchor is required for long
chains; no partial ancestry is treated as verified.

Witnesses must also carry the expected application entry type, including the
integrity zome index, before decoding. A TimeSeal contains an evidence field
and could otherwise deserialize as a TimeAnchor. Cryptographic verification
remains mandatory after the type check.

These are coordinator changes; integrity definitions, DNA properties and
migration policy are unchanged. The signed conductor scenario covers an actual
descendant anchor lookup and rejection of a seal supplied as an anchor. Native
tests cover the ancestry limit and integer overflow. Caller-supplied evidence
continues to report evidence_complete=false and cannot establish global absence
of contradictory evidence.
