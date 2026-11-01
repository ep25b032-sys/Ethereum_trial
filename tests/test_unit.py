import json, os, re, pathlib, pytest, warnings
warnings.simplefilter("ignore")
from aegis.scrubber import Scrubber
from aegis.units import parse_amount, fmt_amount
from aegis.policy import Policy, Decoded
from aegis.txcodec import build_tx, decode_tx, tx_digest, matches_intent
from aegis.signer import Signer, ApprovalGate, SigningRefused, create_keystore
from aegis.chain import local_chain, deploy_env, default_policy
from aegis.evalkit import KS, PASS, ADDRESS, KEY_HEX
import tempfile

def fx():
    d = tempfile.mkdtemp(); c = local_chain(); env = deploy_env(c, ADDRESS); pp = d + "/p.json"; pol = Policy(default_policy(env), pp); pol.save()
    g = ApprovalGate(); s = Signer(KS, lambda: PASS, g, pp); return c, env, pol, g, s

def test_scrubber_keys_and_seed():
    s = Scrubber(); assert "REDACTED" in s.scrub("0x" + "ab" * 32) and "REDACTED" in s.scrub("ab" * 32)
    assert "REDACTED" in s.scrub("witch collapse practice feed shame open despair creek road again ice least")
    assert s.scrub("send 5 tUSD to alice please") == "send 5 tUSD to alice please"
    h = "0x" + "cd" * 32; s.register_public(h); assert s.scrub(h) == h        # tx hashes survive
    s.register_secret("hunter2-pass"); assert "hunter2-pass" not in s.scrub("pw hunter2-pass")

@pytest.mark.parametrize("bad", ["-1", "1e18", "0x10", "1,5", "", "abc", " "])
def test_amount_parser_rejects(bad):
    with pytest.raises(ValueError): parse_amount(bad, 18)
def test_amount_precision(): 
    assert parse_amount("0.000001", 6) == 1 and fmt_amount(25_000_000, 6) == "25"
    with pytest.raises(ValueError): parse_amount("0.0000001", 6)

def test_decoder_roundtrip_all_kinds():
    c, env, pol, g, s = fx()
    for intent in [{"kind": "eth_transfer", "to": env["alice"], "asset": "ETH", "amount": 10**17},
                   {"kind": "erc20_transfer", "to": env["bob"], "asset": "tUSD", "amount": 5 * 10**6},
                   {"kind": "erc20_approve", "to": env["vault"], "asset": "tUSD", "amount": 7 * 10**6}]:
        tx = build_tx(intent, pol, c.w3, ADDRESS); assert matches_intent(decode_tx(tx, pol), intent)

def test_decoder_flags_unknown_calldata():
    c, env, pol, g, s = fx()
    tx = {"to": env["token"], "value": 0, "data": "0xdeadbeef" + "00" * 64, "chainId": env["chain_id"]}
    assert decode_tx(tx, pol).kind == "unknown" and not pol.check(decode_tx(tx, pol), []).ok

def test_signer_requires_approval_and_exact_digest():
    c, env, pol, g, s = fx()
    tx = build_tx({"kind": "eth_transfer", "to": env["alice"], "asset": "ETH", "amount": 10**16}, pol, c.w3, ADDRESS)
    with pytest.raises(SigningRefused): s.sign(tx, None)                                     # unchecked signing impossible
    ap = g.issue(tx_digest(tx), "user")
    with pytest.raises(SigningRefused): s.sign({**tx, "value": tx["value"] + 1}, ap)          # approved digest != tx
    ap2 = g.issue(tx_digest(tx), "user"); s.sign(tx, ap2)
    with pytest.raises(SigningRefused): s.sign(tx, ap2)                                       # replay refused
    forged = dict(g.issue(tx_digest(tx), "user")); forged["mac"] = "0" * 64
    with pytest.raises(SigningRefused): s.sign(tx, forged)                                    # forged approval refused

def test_signer_rechecks_policy_from_disk():
    c, env, pol, g, s = fx()
    tx = build_tx({"kind": "erc20_approve", "to": env["vault"], "asset": "tUSD", "amount": 10**6}, pol, c.w3, ADDRESS)
    bad = {**tx, "data": tx["data"][:10] + "0" * 24 + env["attacker"][2:].lower() + tx["data"][74:]}   # spender swapped to attacker
    with pytest.raises(SigningRefused): s.sign(bad, g.issue(tx_digest(bad), "user"))                    # even WITH a valid approval

def test_keystore_encrypted_at_rest_and_no_plaintext_key():
    raw = open(KS).read(); assert KEY_HEX not in raw and "crypto" in json.loads(raw)

def test_eligibility_no_network_or_key_export_in_signing_path():
    root = pathlib.Path(__file__).parent.parent / "aegis"
    for f in ("signer.py", "policy.py", "txcodec.py", "scrubber.py", "grounding.py"):
        src = (root / f).read_text(); assert not re.search(r"^\s*(import|from)\s+(requests|socket|urllib|http)", src, re.M), f
    assert "private_key" not in (root / "agent.py").read_text().lower()   # agent never handles key material

def test_grants_are_scoped_and_expire():
    import time
    c, env, pol, g, s = fx()
    pol.d["grants"].append({"id": "g", "asset": "ETH", "to": env["alice"], "max_per_tx": "0.1", "remaining": "0.15", "expires_at": time.time() + 60})
    mk = lambda to, amt: Decoded("eth_transfer", recipient=to, asset="ETH", amount=amt, decimals=18)
    assert pol.find_grant(mk(env["alice"], 10**17)); assert not pol.find_grant(mk(env["alice"], 2 * 10**17))   # per-tx limit
    assert not pol.find_grant(mk(env["bob"], 10**16))                                                          # other recipient
    pol.d["grants"][0]["expires_at"] = time.time() - 1; assert not pol.find_grant(mk(env["alice"], 10**16))     # expired
