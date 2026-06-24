# infrix-verify

**The node-free, offline proof verifier for [Infrix](https://github.com/opendlt/infrix-accumen).**

`infrix-verify` is the Tier-1 verification module extracted from the Infrix
monorepo. It independently checks an Infrix proof — a portable evidence package —
**without trusting the node that produced it**. It is the same verifier the
`infrix verify` CLI runs and the hosted playground runs client-side, so a proof
verified here is verified the way anyone else would verify it.

It depends only on the published [`infrix-schema`](https://github.com/opendlt/infrix-schema)
contract module, crypto, and the Go standard library — enforced by a
verifier-isolation fence, so it carries **no compile-time dependency on, and no
trust in, the live node**.

## Install

```sh
go get github.com/opendlt/infrix-verify@latest
```

```go
import (
    "github.com/opendlt/infrix-verify/verifykit"
    "github.com/opendlt/infrix-verify/proofreceipt"
)

// rep := verifykit.Verify(ctx, pkg, verifykit.Options{})  // offline; caps at L3
// receipt := proofreceipt.FromVerifyReport(rep, proofreceipt.VerifyConvertOptions{...})
```

## Packages

| Package | What it does |
|---------|--------------|
| `verifykit` | The full offline verification pipeline: cryptographic binding, Merkle inclusion, optional live-L0 anchor confirmation (L4), deterministic replay, and witness-quorum checks. Returns a machine-readable `Report`; never panics. |
| `witness` | The independent witness-attestation leaf (receipt verification, key-page authorization, freshness). |
| `proofreceipt` | Converts a `verifykit.Report` into the canonical `infrix-schema` proof receipt — the mapping never inflates the report. |

## Trust model

- **No node trust.** `Report.TrustsInfrixNode` is always `false`. The verdict
  comes from cryptography, not the node's word.
- **Honest levels.** Anonymous / offline verification caps at **L3** (batch
  inclusion). **L4** (live L0 settlement) is reached only when an
  `L0AnchorConfirmer` confirms the anchor against the ledger directly — trusting
  the public ledger, never the Infrix node.
- **Isolation fence.** A test asserts the module imports only `infrix-schema`,
  crypto, and stdlib, so it can never silently grow a dependency on the runtime.

## License

MIT — see [LICENSE](LICENSE).
