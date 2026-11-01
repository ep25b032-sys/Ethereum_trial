"""Intent grounding: every value that can move funds (recipient, amount, asset, spender, URL, verb) must be traceable to the
TRUSTED channel (the user's own message) or to the user-owned address book. Untrusted content (web pages, documents, tool
output) is never a grounding source, so injected text cannot supply or alter a value that reaches the signer."""
import re
from decimal import Decimal, InvalidOperation
from web3 import Web3
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
URL = re.compile(r"https?://[^\s<>\"')]+")
SEND_VERBS = r"\b(send|transfer|pay|give|move|wire|tip)\b"
APPROVE_VERBS = r"\b(approve|allow|authori[sz]e|permit|let)\b"
DEPOSIT_VERBS = r"\b(deposit|stake|put|lock|supply)\b"
VERBS = {"send": SEND_VERBS, "approve": APPROVE_VERBS, "deposit": DEPOSIT_VERBS}

def addresses(text): return {a.lower() for a in ADDR.findall(text)}
def bad_checksum_addresses(text):
    out = []
    for a in ADDR.findall(text):
        if a != a.lower() and a[2:] != a[2:].upper() and not Web3.is_checksum_address(a): out.append(a)
    return out
def numbers(text):
    t = ADDR.sub(" ", text); t = URL.sub(" ", t); out = set()
    for m in re.finditer(r"(?<![\w.])\d[\d,]*(?:\.\d+)?", t):
        try: out.add(Decimal(m.group(0).replace(",", "")))
        except InvalidOperation: pass
    return out
def words(text): return set(re.findall(r"[a-z0-9_.\-]+", text.lower()))
def assets_mentioned(text, symbols):
    w = words(text); out = {s for s in symbols if s.lower() in w}
    if "eth" in w or "ether" in w: out.add("ETH")
    return out
def labels_mentioned(text, labels): w = words(text); return {l for l in labels if l.lower() in w}
def urls(text): return {u.rstrip(".,;") for u in URL.findall(text)}
def has_verb(text, action): return bool(re.search(VERBS[action], text.lower()))
def ens_like(text): return set(re.findall(r"\b[a-z0-9\-]+\.eth\b", text.lower()))
