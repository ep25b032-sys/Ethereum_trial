# Aegis Wallet

An access layer between an open-source LLM and an Ethereum wallet. The model only proposes actions as JSON. Deterministic code validates every proposal, shows a confirmation rendered from the decoded transaction, and signs locally. There are no team-held keys and no server-side signing.

**Demo video:** https://drive.google.com/drive/folders/1iOMl8Ax49LPlal2DcNSWYalBCDEwzLVq?usp=sharing

**Architecture diagram:** [docs/architecture.svg](docs/architecture.svg) and [docs/architecture.pdf](docs/architecture.pdf). Editable sources: [scripts/make_diagram.py](scripts/make_diagram.py) and [docs/architecture.mmd](docs/architecture.mmd).

**Failures and trade-offs:** [docs/FAILURE_ANALYSIS.md](docs/FAILURE_ANALYSIS.md)

**Test results:** [results/](results/)

## How it works

1. **Model proposes.** The model outputs a JSON proposal only. It never sees keys.
2. **Grounding.** The recipient, amount, asset and verb must appear in the user's own message. Web pages and documents can never supply a value.
3. **Builder and decoder.** The layer builds the calldata itself. An independent decoder must reproduce the user's intent exactly.
4. **Policy.** Per-transaction and 24-hour caps, contract and function allowlists, and a spend ledger. Unlimited approvals are never allowed.
5. **Confirmation.** The prompt is rendered from the decoded transaction, not from the model's description. Approval is a one-time token bound to the exact transaction digest.
6. **Signer.** It re-checks the policy file on disk and decrypts the key from a local encrypted keystore only at sign time.

Three states are kept explicit: explain, prepare, sign. Ambiguous requests get a clarification question instead of a guess.

## Headline results

| Configuration (stand-in model, 25 attack cases, user always clicks yes) | Attacks that succeed |
|---|---|
| Naive (model output goes straight to the transaction) | 20/25 |
| + policy | 13/25 |
| + grounding | 3/25 |
| + decode check, simulation, calldata-based confirmation | 2/25 |
| Full design (+ secret scrubber, signer re-check) | 0/25 |

Real local LLM (`qwen2.5:3b-instruct` via Ollama), full design:

- Attack cases with any harm: **0/25**
- Legitimate tasks completed: **7/8** (the one failure is a benign page summary; the model asked a question instead. A safe failure.)
- Ambiguous requests answered with a question: **7/7**

Privacy flows (what the model, RPC node and web each see) are in `results/privacy_flows.md`.

## Run it

```
pip install -r requirements.txt
python -m aegis.cli demo
python scripts/run_suite.py
```

With a real local model:

```
ollama pull qwen2.5:3b-instruct
python scripts/check_llm.py
python scripts/run_llm_suite.py
python -m aegis.cli chat --model ollama:qwen2.5:3b-instruct --trace
```

Use `python -m aegis.cli chat --model worst-case --trace` to watch a simulated malicious model get blocked.

## Evidence files in results/

- `llm_check.md` / `llm_check.json`: 11-prompt check against the real model
- `llm_suite_qwen2.5_3b-instruct.md` / `.json`: full 40-case suite with the real model
- `ollama_chat_transcript.txt`: interactive session with `--trace`
- `ollama_list.txt`: the local model list
- `privacy_flows.md`: measured privacy table

## What is not done / known limitations

- Runs on an in-process local EVM, not a public testnet such as Sepolia.
- The attack suite was written by the same author as the defences. 0/25 shows coverage of these attacks, not unbreakability.
- The signer shares a process with the agent.
- ENS is not supported, and addresses the user types in full are trusted.
- Real-LLM numbers come from one run of one 3B model with temperature not varied.

See [docs/FAILURE_ANALYSIS.md](docs/FAILURE_ANALYSIS.md) for the full list.

## Tasks handled and what each signature authorises

Only on-chain transactions are signed. There is no off-chain message signing. Every signature is for one transaction whose bytes were built by the access layer, decoded back independently, and approved by the user against a digest.

| Task | What the signature authorises |
|---|---|
| Send ETH to a contact or a full 0x address | Transfer of exactly the confirmed amount to exactly the confirmed address |
| Send tUSD (ERC-20) | `transfer` of the confirmed amount to the confirmed address |
| Approve tUSD for the vault | `approve` of the exact confirmed amount to the allowlisted vault only. Unlimited approvals are never allowed |
| Deposit tUSD into the vault | `deposit` of the confirmed amount into the allowlisted vault |
| Balance, contact list, read a web page | No signature. These are read-only or explain-only |

Standing grants (ongoing permissions) are set by the user in `policy.json`, outside the model path, and are scoped by spender, asset and cap.

## Existing components used (and what each can access)

| Component | Role | Access to information and signing authority |
|---|---|---|
| Ollama + `qwen2.5:3b-instruct` | Open-source model that turns natural language into a JSON proposal | Sees the scrubbed user sentence and contact labels only. No keys, no addresses, no balances. Cannot sign |
| web3.py 8.0.0 | RPC client | Sends reads and the already-signed transaction. No key access |
| eth-account 0.14.0 | Signing and keystore encryption library | Used only inside the signer, at sign time |
| eth-tester 0.14.0b1 + py-evm 0.12.1b1 | Reproducible in-process local EVM | Local only, no network |
| requests | Fetches pages the user explicitly links | Outbound HTTP only to URLs the user typed |
| Solidity (`contracts/TestToken.sol`, `contracts/Vault.sol`), compiled via `scripts/compile.js` | Test token and vault used for the demo | Local test chain only |
| pytest | Test runner | None |

## Access-layer functionality we built

All of `aegis/`: the strict proposal schema and model adapters (`models.py`), grounding and ambiguity checks (`grounding.py`), deterministic transaction builder and independent decoder (`txcodec.py`), policy engine with caps, allowlists and 24-hour ledger (`policy.py`), secret scrubber (`scrubber.py`), signer with keystore and approval-token check (`signer.py`), untrusted web-content handling (`webtool.py`), agent loop (`agent.py`), CLI (`cli.py`), and the evaluation harness (`evalkit.py`), plus the attack suite in `tests/` and `scripts/`.

## What becomes public, and what the system adds to it

A transfer, approval or deposit publishes the sender, the recipient or contract, the amount, and the timing. That is public by design on Ethereum. The access layer builds the calldata itself and adds no memo or note, so the user's reason for the payment, contact names, and anything said to the model never go on-chain. The RPC node sees the signed transaction and read calls. The model sees only the scrubbed sentence and contact labels. The measured table is in `results/privacy_flows.md`.

## Resource usage

- No GPU and no network needed for the 400-run attack suite (`python scripts/run_suite.py`), which takes about 45 seconds on a laptop.
- Real-model runs use Ollama with `qwen2.5:3b-instruct`, a 1.9 GB download (`results/ollama_list.txt`). Per-request latency in `results/llm_suite_qwen2.5_3b-instruct.json` ranges from about 0.3 s to 4.6 s on an Apple Silicon MacBook, and the first call is slowest because of model load.
- Peak memory of the suite run: about 100 MB (measured with `/usr/bin/time -l python scripts/run_suite.py`, maximum resident set size).
- Python 3.13, macOS (Apple Silicon). Dependencies are pinned in `requirements.txt`.
