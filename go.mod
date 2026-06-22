// infrix-verify: the node-free Tier-1 verification module extracted from the
// Infrix monorepo (docs/extraction-plan). It carries the offline proof
// verifier (verifykit) and the witness attestation leaf. It depends only on
// the published infrix-schema contract module, crypto, and the Go standard
// library (enforced by the verifier-isolation fence) so it can be consumed as
// an independent, versioned module with no trust in — and no compile-time
// dependency on — the live node.
module github.com/AccumulateNetwork/infrix-verify

go 1.25.7

require github.com/opendlt/infrix-schema v0.1.0
