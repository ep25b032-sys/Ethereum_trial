"""Access layer: model proposes -> layer validates -> user confirms (from decoded calldata) -> signer signs -> chain.
Every stage after the model is deterministic code. The model cannot reach keys, policy, signer, or the chain."""
import json, os, re, time
from dataclasses import dataclass, field
from decimal import Decimal
from web3 import Web3
from .scrubber import Scrubber
from .policy import Policy, Decoded, Decision
from .units import parse_amount, fmt_amount
from .txcodec import build_tx, decode_tx, tx_digest, matches_intent
from .signer import SigningRefused
from . import grounding as G
from .models import SYSTEM_PROMPT

ALLOWED_KEYS = {"action", "to", "spender", "amount", "asset", "url", "question", "text", "description", "reasoning"}
ACTIONS = {"send", "approve", "deposit", "balance", "contacts", "explain", "clarify", "fetch_url"}

@dataclass
class LayerConfig:
    scrub: bool = True; policy: bool = True; grounding: bool = True; ambiguity: bool = True
    roundtrip: bool = True; simulation: bool = True; calldata_confirm: bool = True; signer_recheck: bool = True
PRESETS = {
    "A0_naive":         LayerConfig(False, False, False, False, False, False, False, False),
    "A1_+policy":       LayerConfig(False, True, False, False, False, False, False, False),
    "A2_+grounding":    LayerConfig(False, True, True, True, False, False, False, False),
    "A3_+verify":       LayerConfig(False, True, True, True, True, True, True, False),
    "A4_full":          LayerConfig(True, True, True, True, True, True, True, True),
}

@dataclass
class Summary: text: str; digest: str; decoded: Decoded; flags: list; description: str

@dataclass
class Result:
    status: str            # executed | needs_clarification | blocked | declined | explained | info
    message: str = ""
    tx_hash: str = ""
    decoded: Decoded = None
    trace: list = field(default_factory=list)
    egress: dict = field(default_factory=dict)

class Agent:
    def __init__(self, chain, policy_path, signer, gate, confirmer, model, web=None, scrubber=None, cfg=None, audit_path=None, ledger_path=None):
        self.chain, self.policy_path, self.signer, self.gate = chain, policy_path, signer, gate
        self.confirmer, self.model, self.web = confirmer, model, web
        self.sc = scrubber or Scrubber(); self.cfg = cfg or LayerConfig()
        self.ledger, self.known, self.audit, self.audit_path = [], set(), [], audit_path
        self.ledger_path = ledger_path       # persisted so the 24h cap survives restarts
        if ledger_path and os.path.exists(ledger_path):
            with open(ledger_path) as f: self.ledger = [tuple(x) for x in json.load(f)]
        self.egress = {"model_prompts": [], "http": []}
        self.builder_fault = None; self.tx_mutator = None   # fault-injection hooks used ONLY by the test-suite

    # ---------- helpers ----------
    def _s(self, x): return self.sc.scrub(x) if self.cfg.scrub else x
    def _log(self, entry):
        entry = self.sc.scrub_obj(entry) if self.cfg.scrub else entry
        self.audit.append(entry)
        if self.audit_path:
            with open(self.audit_path, "a") as f: f.write(json.dumps(entry, default=str) + "\n")
    def _done(self, status, message, trace, mark, dec=None, tx_hash=""):
        eg = {"rpc_methods": sorted({c["method"] for c in self.chain.rpc_log[mark:]}), "http": list(self.egress["http"])}
        self._log({"t": time.time(), "status": status, "message": message, "trace": trace, "tx": tx_hash, "egress": eg})
        return Result(status, self._s(message) + getattr(self, "_warn", ""), tx_hash, dec, trace, eg)

    def _system(self, pol):
        return SYSTEM_PROMPT.replace("{contacts}", ", ".join(pol.contacts)).replace("{tokens}", ", ".join(["ETH"] + list(pol.tokens))).replace("{spenders}", ", ".join(pol.spenders))

    def _wrap(self, content, src):
        c = re.sub(r"</?\s*untrusted_content[^>]*>", "[filtered-tag]", self._s(content))[:4000]   # block delimiter-escape attempts
        return f'<untrusted_content source="{src}">\n{c}\n</untrusted_content>'

    def _parse(self, raw):
        try: p = json.loads(raw)
        except Exception: return None, "model output was not valid JSON"
        if not isinstance(p, dict) or p.get("action") not in ACTIONS: return None, "model proposed an unknown action"
        extra = set(p) - ALLOWED_KEYS
        if extra: return None, f"proposal contains forbidden fields {sorted(extra)} (models may not supply calldata/gas/etc.)"
        if any(not isinstance(v, str) for v in p.values()): return None, "proposal fields must be strings"
        return p, None

    # ---------- main entry ----------
    def handle(self, user_text, docs=None) -> Result:
        pol = Policy.load(self.policy_path); tr = []; mark = len(self.chain.rpc_log); self.egress["http"] = []
        ut = self._s(user_text); self._warn = ""
        if ut != user_text:
            tr.append("scrubber: removed key/seed-like content from the user's message before the model saw it")
            self._warn = "  [WARNING: your message contained what looks like a private key/seed phrase. It was removed before reaching the model or any log. Treat that secret as exposed and rotate it.]"
        messages = [{"role": "system", "content": self._system(pol)}, {"role": "user", "content": ut}]
        for d in docs or []:
            messages.append({"role": "tool", "content": self._wrap(d, "attachment")})
        prop = None
        for step in range(3):
            self.egress["model_prompts"].append(json.loads(json.dumps(messages)))
            try: raw = self.model.propose(messages)
            except Exception as e: return self._done("blocked", f"Model unavailable: {e}", tr, mark)
            prop, err = self._parse(self._s(raw))
            if err: return self._done("blocked", "Rejected model output: " + err, tr + [f"raw: {self._s(raw)[:200]}"], mark)
            tr.append(f"model proposed: {json.dumps(prop)[:300]}")
            if prop["action"] != "fetch_url": break
            url = prop.get("url", "")
            if self.cfg.grounding and url not in G.urls(user_text):
                return self._done("blocked", "Refused to fetch a URL you did not type yourself (possible data-exfiltration attempt).", tr, mark)
            self.egress["http"].append(self._s(url)); tr.append(f"fetched {self._s(url)} (content treated as untrusted data)")
            try: content = self.web.fetch(url)
            except Exception as e: content = f"(fetch failed: {e})"
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "tool", "content": self._wrap(content, self._s(url))})
        else: return self._done("blocked", "too many tool steps", tr, mark)
        a = prop["action"]
        if a == "fetch_url": return self._done("blocked", "no final action", tr, mark)
        if a == "explain": return self._done("explained", "Model says (unverified, text only): " + prop.get("text", "")[:500], tr, mark)
        if a == "clarify": return self._done("needs_clarification", prop.get("question", "Could you clarify?"), tr, mark)
        if a == "balance": return self._done("info", self._balances(pol), tr, mark)
        if a == "contacts":
            c = "; ".join(f"{k} ({v[:8]}...{v[-4:]})" for k, v in pol.contacts.items()) or "none"
            return self._done("info", f"You can send ETH/{'/'.join(pol.tokens)} to: {c}, or to any 0x address you type in full. Approvals/deposits go only to: {', '.join(pol.spenders) or 'none'}.", tr, mark)
        return self._transact(prop, user_text, pol, tr, mark)

    def _balances(self, pol):
        w3, me = self.chain.w3, self.signer.address; out = [f"ETH: {fmt_amount(w3.eth.get_balance(me), 18)}"]
        for sym, t in pol.tokens.items():
            r = w3.eth.call({"to": t["address"], "data": "0x70a08231" + "0" * 24 + me[2:].lower()})
            out.append(f"{sym}: {fmt_amount(int(r.hex(), 16), t['decimals'])}")
        return "Balances (computed locally, never sent to the model): " + "; ".join(out)

    def _resolve(self, prop, ut, pol):
        """Returns (intent, None) | (None, ('clarify'|'block', msg))."""
        c, act = self.cfg, prop["action"]
        key = "spender" if act == "approve" else "to"
        to, amt, asset = prop.get(key), prop.get("amount"), prop.get("asset")
        if act == "deposit" and not to: to = "vault"
        miss = [n for n, v in (("amount", amt), ("asset", asset), ("recipient" if act == "send" else "target", to)) if not v]
        if miss: return None, ("clarify", "I need: " + ", ".join(miss) + ".")
        if not (asset == "ETH" and act == "send") and asset not in pol.tokens: return None, ("block", f"unsupported asset {asset!r}")
        try: units = parse_amount(amt, pol.decimals(asset))
        except ValueError as e: return None, ("block", f"invalid amount: {e}")
        pool = pol.contacts if act == "send" else pol.spenders
        if c.ambiguity:
            if G.bad_checksum_addresses(ut): return None, ("clarify", "An address in your message has an invalid checksum (typo?). Please re-check it.")
            if G.ens_like(ut): return None, ("clarify", "I can't resolve ENS names in offline mode. Please give a 0x address or add a contact.")
            nums = G.numbers(ut)
            if len(nums) > 1: return None, ("clarify", f"I see several amounts ({', '.join(sorted(map(str, nums)))}). Which one do you mean?")
            cands = G.labels_mentioned(ut, pool) | G.addresses(ut)
            if len(cands) > 1: return None, ("clarify", "I see more than one possible recipient/target. Which one?")
            if len(G.assets_mentioned(ut, list(pol.tokens))) > 1: return None, ("clarify", "Which asset do you mean?")
        if c.grounding:
            if not G.has_verb(ut, act): return None, ("block", "Your message did not ask for this action; the proposal did not come from you.")
            nums = G.numbers(ut)
            if not nums: return None, ("clarify", "I couldn't find an amount in your message. How much?")
            if Decimal(amt) not in nums: return None, ("block", f"Proposed amount {amt} does not match what you wrote.")
            am = G.assets_mentioned(ut, list(pol.tokens))
            if not am and act == "send": return None, ("clarify", "Which asset: ETH or a token?")
            if am and asset not in am and act != "deposit": return None, ("block", f"Proposed asset {asset} does not match what you wrote.")
            ok_set = G.labels_mentioned(ut, pool) | G.addresses(ut)
            if not ok_set and act != "deposit": return None, ("clarify", "Who should receive it?")
            if to.lower() not in {x.lower() for x in ok_set} and not (act == "deposit" and to.lower() in pool):
                return None, ("block", "Proposed recipient/target does not match what you wrote (possible tampering or injection).")
        if to.lower() in pool: addr = pool[to.lower()]
        elif G.ADDR.fullmatch(to): addr = Web3.to_checksum_address(to)
        else: return None, ("clarify", f"I don't know who {to!r} is. Give a 0x address or add them as a contact.")
        kind = {"send": "eth_transfer" if asset == "ETH" else "erc20_transfer", "approve": "erc20_approve", "deposit": "vault_deposit"}[act]
        return {"kind": kind, "to": addr, "asset": asset, "amount": units}, None

    def _transact(self, prop, ut_raw, pol, tr, mark):
        c = self.cfg; ut = self._s(ut_raw); w3 = self.chain.w3; me = self.signer.address
        intent, err = self._resolve(prop, ut_raw if not c.scrub else ut, pol)
        if err: return self._done("needs_clarification" if err[0] == "clarify" else "blocked", err[1], tr, mark)
        tr.append(f"validated intent: {intent['kind']} {fmt_amount(intent['amount'], pol.decimals(intent['asset']))} {intent['asset']} -> {intent['to']}")
        try: tx = build_tx(intent, pol, w3, me, estimate=c.simulation)
        except Exception as e: return self._done("blocked", f"Simulation failed (would revert): {str(e)[:150]}", tr, mark)
        if self.builder_fault: tx = self.builder_fault(tx)
        dec = decode_tx(tx, pol) if c.roundtrip or c.policy else Decoded(intent["kind"], tx["to"], intent["to"], intent["asset"], amount=intent["amount"], decimals=pol.decimals(intent["asset"]), value=tx["value"], chain_id=tx["chainId"], sender=me)
        if c.roundtrip and not matches_intent(dec, intent): return self._done("blocked", "Built transaction does not decode to the validated intent (internal fault or tampering).", tr, mark, dec)
        fee = tx["gas"] * tx["gasPrice"]
        if c.simulation:
            need = tx["value"] + fee
            if w3.eth.get_balance(me) < need: return self._done("blocked", "Insufficient ETH for value + gas.", tr, mark, dec)
        flags = []
        if c.policy:
            d = pol.check(dec, self.ledger, known_recipients=self.known); flags = d.flags
            if fee > parse_amount(pol.d.get("max_fee_eth", "0.01"), 18): d.ok = False; d.reasons.append("gas fee above max_fee_eth")
            if not d.ok: return self._done("blocked", "Policy: " + "; ".join(d.reasons), tr, mark, dec)
            tr.append(f"policy ok; flags={flags}")
        digest = tx_digest(tx)
        grant = pol.find_grant(dec) if (c.policy and "NEW_RECIPIENT" not in flags) else None
        if grant: approval = self.gate.issue(digest, "grant:" + grant["id"]); tr.append(f"auto-approved by standing grant {grant['id']}")
        else:
            summ = self._summary(dec, pol, flags, fee, prop.get("description", ""), digest)
            if not self.confirmer.confirm(summ): return self._done("declined", "You declined; nothing was signed.", tr + ["user declined"], mark, dec)
            approval = self.gate.issue(digest, "user"); tr.append("user approved exact digest " + digest[:12])
        if self.tx_mutator: tx = self.tx_mutator(tx)    # test hook: malware tampering after approval
        try: raw = self.signer.sign(tx, approval)
        except SigningRefused as e: return self._done("blocked", f"Signer refused: {e}", tr, mark, dec)
        h = w3.eth.send_raw_transaction(raw); rc = w3.eth.wait_for_transaction_receipt(h); hx = h.hex() if h.hex().startswith("0x") else "0x" + h.hex()
        self.sc.register_public(hx); self.known.add(intent["to"])
        if dec.kind in ("eth_transfer", "erc20_transfer"):
            self.ledger.append((time.time(), dec.asset, dec.amount))
            if self.ledger_path:
                with open(self.ledger_path, "w") as f: json.dump([x for x in self.ledger if time.time() - x[0] < 86400], f)
        if grant: pol.consume_grant(grant, dec)
        ok = rc.status == 1; tr.append(f"signed locally + broadcast; receipt status={rc.status}")
        return self._done("executed" if ok else "blocked", f"{'Done' if ok else 'On-chain revert'}: {dec.kind} {dec.human()} {dec.asset} -> {dec.recipient}. tx {hx}", tr, mark, dec, hx)

    def _summary(self, dec, pol, flags, fee, desc, digest):
        if not self.cfg.calldata_confirm:
            return Summary(f"Model proposes: {desc}", digest, dec, flags, desc)
        lab = {v.lower(): k for k, v in {**pol.contacts, **pol.spenders}.items()}
        who = f"{dec.recipient}" + (f" [{lab[dec.recipient.lower()]}]" if dec.recipient.lower() in lab else " [NOT IN YOUR CONTACTS]")
        verb = {"eth_transfer": "SEND", "erc20_transfer": "SEND", "erc20_approve": "ALLOW SPENDING", "vault_deposit": "DEPOSIT"}[dec.kind]
        lines = [f"{verb} {dec.human()} {dec.asset}", f"  to/for: {who}", f"  chain id: {dec.chain_id}   max network fee: {fmt_amount(fee, 18)} ETH",
                 f"  digest: {digest[:16]}  (decoded from the raw transaction bytes, not from the model's description)"]
        if "NEW_RECIPIENT" in flags: lines.append("  !! WARNING: first time sending to this address")
        if "revoke" in flags: lines.append("  (this REVOKES an allowance)")
        lines.append(f"  model's own description (unverified): {desc}")
        return Summary("\n".join(lines), digest, dec, flags, desc)

class CLIConfirmer:
    def confirm(self, s: Summary):
        print("\n" + "=" * 60 + "\nCONFIRM TRANSACTION\n" + s.text + "\n" + "=" * 60)
        return input(f"Type 'yes {s.digest[:6]}' to sign, anything else to cancel: ").strip() == f"yes {s.digest[:6]}"
