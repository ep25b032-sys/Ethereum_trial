# Architecture and trust boundaries
See `architecture.svg` (editable: `scripts/make_diagram.py`, `architecture.mmd`).

## Principle
The LLM is an **untrusted proposer**. It emits one JSON object. Every later stage is deterministic code that can only *narrow* what the model asked for, never widen it.

## Stages (`aegis/agent.py`)
| # | Stage | Enforces | File |
|---|---|---|---|
| 0 | Scrubber | keys/seed/passphrase never reach model, logs, or egress | `scrubber.py` |
| 1 | Strict parse | closed action set; unknown fields (`data`, `gas`, `to` of a contract...) rejected; all fields strings | `agent._parse` |
| 2 | Grounding + ambiguity | verb, amount, asset, recipient/spender and fetched URL must appear in the **user's own message** (or user-owned address book). Missing -> *ask*. Mismatched -> *block*. Several amounts/recipients, ENS names, bad EIP-55 checksum -> *ask* | `grounding.py`, `agent._resolve` |
| 3 | Builder | the layer encodes calldata (`transfer/approve/deposit`) from the validated intent | `txcodec.build_tx` |
| 4 | Decode + simulate | an independent raw-bytes decoder must reproduce the intent exactly; `estimateGas` (reverts => blocked), balance >= value+gas | `txcodec.decode_tx` |
| 5 | Policy | enabled actions, chain id, per-tx and 24h caps (persisted ledger), token/spender allowlists, no unlimited approval, no token-contract / zero recipient, fee cap | `policy.py` |
| 6 | Approval | confirmation text is rendered **from the decoded tx**; user approval (or a scoped standing grant) mints a one-time HMAC token bound to `sha256(tx)` | `agent._summary`, `signer.ApprovalGate` |
| 7 | Signer | verifies token == digest of the exact tx being signed (anti-TOCTOU, replay-proof), re-decodes and re-checks the **policy file on disk**, decrypts key only now | `signer.py` |

## What the three actions mean (explain / prepare / sign)
*Explain*: `explain`, `balance`, `clarify` actions never build a tx (balances are rendered by templates; the model never sees them). *Prepare*: stages 1-6 produce an unsigned tx plus a human summary; nothing is signed. *Sign*: only after an explicit, digest-bound approval; each signature authorises exactly one decoded transaction (on-chain only; no off-chain/EIP-712 signing is exposed).

## Who can change what
| Asset | Model | Untrusted content | User | Layer code |
|---|---|---|---|---|
| Private key | no path | no path | passphrase | Signer only |
| policy.json | no tool | no tool | CLI `/grant /contact /allow-spender` or editor | read-only |
| Recipient / amount | proposes, cannot change what is grounded | cannot supply | types it | validates |

## Components reused
web3.py/eth-account (ABI, signing, keystore v3), eth-tester/py-evm (local chain), solc (test contracts), optional Ollama LLM. Built here: everything in `aegis/`.
