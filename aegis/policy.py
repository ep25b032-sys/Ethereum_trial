"""User-owned policy. Loaded from a JSON file that ONLY the user edits (CLI `grant`/`allow` commands or a text editor).
There is deliberately no model-reachable tool that can modify it."""
import json, time, hashlib
from dataclasses import dataclass, field
from decimal import Decimal
from .units import parse_amount, MAX_UINT, fmt_amount
ZERO = "0x" + "0" * 40

@dataclass
class Decoded:
    kind: str                     # eth_transfer | erc20_transfer | erc20_approve | vault_deposit | unknown
    target: str = ""              # tx.to
    recipient: str = ""           # transfer recipient / approve spender / vault address
    asset: str = ""               # ETH or token symbol
    token_address: str = ""
    amount: int = 0               # base units
    decimals: int = 18
    value: int = 0
    chain_id: int = 0
    sender: str = ""
    def human(self): return fmt_amount(self.amount, self.decimals)

@dataclass
class Decision:
    ok: bool
    reasons: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    grant_id: str = ""

class Policy:
    def __init__(self, data: dict, path: str = ""):
        self.d, self.path = data, path
    @classmethod
    def load(cls, path):
        with open(path) as f: return cls(json.load(f), path)
    def save(self, path=None):
        with open(path or self.path, "w") as f: json.dump(self.d, f, indent=2)
    def digest(self): return hashlib.sha256(json.dumps(self.d, sort_keys=True).encode()).hexdigest()
    # lookups
    @property
    def chain_id(self): return self.d["chain_id"]
    @property
    def tokens(self): return self.d["tokens"]                 # symbol -> {address, decimals}
    @property
    def contacts(self): return {k.lower(): v for k, v in self.d["contacts"].items()}
    @property
    def spenders(self): return {k.lower(): v for k, v in self.d["spenders"].items()}
    def token_by_address(self, a):
        for s, t in self.tokens.items():
            if t["address"].lower() == a.lower(): return s, t
        return None, None
    def is_spender(self, a): return a.lower() in {v.lower() for v in self.spenders.values()}
    def decimals(self, asset): return 18 if asset == "ETH" else self.tokens[asset]["decimals"]

    def check(self, dec: Decoded, ledger: list, now: float = None, known_recipients=()) -> Decision:
        now = now or time.time()
        r, fl = [], []
        d = self.d
        if dec.kind == "unknown": return Decision(False, ["unrecognised transaction shape (unknown contract/selector/calldata)"])
        if dec.kind not in d["allowed_actions"]: r.append(f"action {dec.kind} not enabled in policy")
        if dec.chain_id != self.chain_id: r.append("wrong chain id")
        if dec.kind in ("eth_transfer", "erc20_transfer"):
            if dec.recipient.lower() == ZERO: r.append("recipient is the zero address")
            if self.token_by_address(dec.recipient)[0]: r.append("recipient is a token contract (funds would be lost)")
            if dec.amount <= 0: r.append("amount must be positive")
            caps = d["caps"].get(dec.asset)
            if not caps: r.append(f"no spending cap configured for {dec.asset}")
            else:
                per_tx, daily = parse_amount(caps["per_tx"], dec.decimals), parse_amount(caps["daily"], dec.decimals)
                if dec.amount > per_tx: r.append(f"exceeds per-transaction cap ({caps['per_tx']} {dec.asset})")
                spent = sum(a for ts, s, a in ledger if s == dec.asset and now - ts < 86400)
                if spent + dec.amount > daily: r.append(f"exceeds 24h cap ({caps['daily']} {dec.asset}; already spent {fmt_amount(spent, dec.decimals)})")
                if dec.amount * 2 >= per_tx: fl.append("large_relative_to_cap")
            if dec.recipient.lower() not in {v.lower() for v in self.contacts.values()} and dec.recipient.lower() not in {x.lower() for x in known_recipients}:
                fl.append("NEW_RECIPIENT")
        elif dec.kind == "erc20_approve":
            if not self.is_spender(dec.recipient): r.append("spender is not on the allowlist (only you can add it, via /allow-spender in the CLI)")
            if dec.amount >= MAX_UINT // 2: r.append("unlimited approval is never allowed")
            cap = d.get("approve_cap", {}).get(dec.asset)
            if cap is None: r.append(f"no approval cap configured for {dec.asset}")
            elif dec.amount > parse_amount(cap, dec.decimals): r.append(f"approval exceeds approve cap ({cap} {dec.asset})")
            if dec.amount == 0: fl.append("revoke")
        elif dec.kind == "vault_deposit":
            if not self.is_spender(dec.recipient): r.append("deposit target not on allowlist")
            caps = d["caps"].get(dec.asset)
            if not caps or dec.amount > parse_amount(caps["per_tx"], dec.decimals): r.append("deposit exceeds per-tx cap")
        if dec.value and dec.kind != "eth_transfer": r.append("unexpected ETH value on a token call")
        return Decision(not r, r, fl)

    def find_grant(self, dec: Decoded, now=None):
        """Standing permission: user-created, scoped to recipient+asset, with expiry and remaining budget."""
        now = now or time.time()
        if dec.kind not in ("eth_transfer", "erc20_transfer"): return None
        for g in self.d.get("grants", []):
            if g["asset"] == dec.asset and g["to"].lower() == dec.recipient.lower() and g["expires_at"] > now \
               and dec.amount <= parse_amount(g["max_per_tx"], dec.decimals) \
               and parse_amount(g["remaining"], dec.decimals) >= dec.amount:
                return g
        return None
    def consume_grant(self, g, dec):
        g["remaining"] = fmt_amount(parse_amount(g["remaining"], dec.decimals) - dec.amount, dec.decimals)
        if self.path: self.save()
