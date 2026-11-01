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
