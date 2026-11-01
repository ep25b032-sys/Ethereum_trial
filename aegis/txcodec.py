"""Deterministic tx construction (from a VALIDATED intent) and an INDEPENDENT raw-calldata decoder.
The model never supplies calldata, selectors or `to` of a contract call. The decoder re-derives meaning from raw bytes,
so what the user is shown/what the signer checks is the truth about the tx, not the model's description."""
import json, hashlib
from web3 import Web3
from .policy import Decoded, ZERO
SEL = {"transfer": "a9059cbb", "approve": "095ea7b3", "deposit": Web3.keccak(text="deposit(address,uint256)")[:4].hex()}

def _w(x):  # address/int -> 32 byte word hex
    if isinstance(x, int): return f"{x:064x}"
    return "0" * 24 + x.lower().removeprefix("0x")

def build_tx(intent, policy, w3, sender, estimate=True):
    """intent: dict(kind, to, asset, amount(int), token_address?) -> unsigned tx dict (gas filled by estimate)"""
    k = intent["kind"]; base = {"from": sender, "chainId": policy.chain_id, "nonce": w3.eth.get_transaction_count(sender)}
    if k == "eth_transfer": base.update(to=Web3.to_checksum_address(intent["to"]), value=intent["amount"], data="0x")
    else:
        tok = Web3.to_checksum_address(policy.tokens[intent["asset"]]["address"])
        if k == "erc20_transfer": base.update(to=tok, value=0, data="0x" + SEL["transfer"] + _w(intent["to"]) + _w(intent["amount"]))
        elif k == "erc20_approve": base.update(to=tok, value=0, data="0x" + SEL["approve"] + _w(intent["to"]) + _w(intent["amount"]))
        elif k == "vault_deposit":
            base.update(to=Web3.to_checksum_address(intent["to"]), value=0, data="0x" + SEL["deposit"] + _w(tok) + _w(intent["amount"]))
        else: raise ValueError(k)
    base["gasPrice"] = w3.eth.gas_price
    base["gas"] = int(w3.eth.estimate_gas({k2: v for k2, v in base.items() if k2 != "gasPrice"}) * 1.2) if estimate else 150000
    return base

def decode_tx(tx, policy) -> Decoded:
    to = (tx.get("to") or "").lower(); data = (tx.get("data") or "0x")[2:].lower(); val = int(tx.get("value", 0))
    d = Decoded(kind="unknown", target=tx.get("to", ""), value=val, chain_id=int(tx.get("chainId", 0)), sender=tx.get("from", ""))
    if not to: return d
    if data == "":
        d.kind, d.recipient, d.asset, d.amount, d.decimals = "eth_transfer", tx["to"], "ETH", val, 18; return d
    sel, args = data[:8], data[8:]
    if len(args) % 64: return d
    words = [args[i:i + 64] for i in range(0, len(args), 64)]
    addr = lambda w: Web3.to_checksum_address("0x" + w[24:]) if w[:24] == "0" * 24 else None
    sym, tok = policy.token_by_address(to)
    if sym and sel == SEL["transfer"] and len(words) == 2 and addr(words[0]):
        d.kind, d.recipient, d.asset, d.token_address, d.amount, d.decimals = "erc20_transfer", addr(words[0]), sym, tok["address"], int(words[1], 16), tok["decimals"]
    elif sym and sel == SEL["approve"] and len(words) == 2 and addr(words[0]):
        d.kind, d.recipient, d.asset, d.token_address, d.amount, d.decimals = "erc20_approve", addr(words[0]), sym, tok["address"], int(words[1], 16), tok["decimals"]
    elif policy.is_spender(to) and sel == SEL["deposit"] and len(words) == 2 and addr(words[0]):
        s2, t2 = policy.token_by_address(addr(words[0]))
        if s2: d.kind, d.recipient, d.asset, d.token_address, d.amount, d.decimals = "vault_deposit", tx["to"], s2, t2["address"], int(words[1], 16), t2["decimals"]
    return d

def tx_digest(tx) -> str:
    c = {k: (str(tx[k]) if k in ("to", "data", "from") else int(tx[k])) for k in ("from", "to", "value", "data", "nonce", "gas", "gasPrice", "chainId")}
    c["to"], c["from"], c["data"] = c["to"].lower(), c["from"].lower(), c["data"].lower()
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()

def matches_intent(dec: Decoded, intent) -> bool:
    """Round-trip: decoded-from-bytes must equal the validated intent exactly."""
    if dec.kind != intent["kind"] or dec.amount != intent["amount"]: return False
    if dec.asset != intent["asset"]: return False
    return dec.recipient.lower() == intent["to"].lower()
