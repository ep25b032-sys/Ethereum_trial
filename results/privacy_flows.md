# What each party sees (measured from a real run of: `send 25 tUSD to bob`)

| Party | Sees | Does NOT see | Why it needs it |
|---|---|---|---|
| **Model** (local) | the user's sentence, contact *labels* (alice, bob), token symbols; 2216 chars total | private key, passphrase, any contact's 0x address (verified: none present), balances, tx hashes | to turn language into a proposal |
| **RPC node** | methods: eth_chainId, eth_estimateGas, eth_gasPrice, eth_getBalance, eth_getTransactionCount, eth_getTransactionReceipt, eth_sendRawTransaction; the sender, recipient, token, amount in the final signed tx | model prompts, the policy file, the fact that an AI was involved | unavoidable: public transactions reveal sender/recipient/value |
| **Web (only if user links a URL)** | the one URL the user typed | wallet address, balances, prompts | to read the page |
| **Logs (audit.jsonl)** | scrubbed proposals, decoded tx, decisions | secrets (scrubbed before write) | audit/repro |
| **Block explorer / public** | tx sender, recipient, amount, calldata | anything else | inherent to Ethereum |

Public by design for this task: sender, recipient, asset, amount, gas. Unnecessary disclosure avoided: no memo/extra calldata fields exist, the model never sees addresses/balances, results of balance queries are rendered by templates not by the model, and fetch/RPC are the only egress paths (both recorded).
