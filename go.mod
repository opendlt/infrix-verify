// infrix-verify: the node-free Tier-1 verification module extracted from the
// Infrix monorepo (docs/extraction-plan). It carries the offline proof
// verifier (verifykit) and the witness attestation leaf. It depends only on
// the published infrix-schema contract module, crypto, and the Go standard
// library (enforced by the verifier-isolation fence) so it can be consumed as
// an independent, versioned module with no trust in — and no compile-time
// dependency on — the live node.
module github.com/opendlt/infrix-verify

go 1.25.7

require github.com/opendlt/infrix-schema v0.7.2-0.20261127021034-e5e49a20366f

require golang.org/x/sys v0.42.0 // indirect

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	golang.org/x/crypto v0.49.0
)

require (
	github.com/cayleygraph/quad v1.3.0 // indirect
	github.com/piprate/json-gold v0.9.1
	github.com/pquerna/cachecontrol v0.2.0 // indirect
)
