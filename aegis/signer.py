"""Signing authority. Key lives only in an encrypted local keystore; decrypted solely here, solely at sign time, with a
passphrase the USER types (never passes through the model). The signer is a hard gate independent of the agent/model:
 - requires a one-time Approval whose digest equals the digest of the exact tx being signed (anti-TOCTOU/tamper),
 - re-decodes the tx from raw bytes and re-runs the policy against the policy FILE on disk."""
import os, hmac, hashlib, json
from eth_account import Account
from .txcodec import decode_tx, tx_digest
from .policy import Policy

class SigningRefused(Exception): pass

class ApprovalGate:
    """Mints approvals. Only the confirmation path (human or grant) holds a reference to this."""
    def __init__(self): self._k = os.urandom(32); self._used = set()
    def issue(self, digest: str, via: str):
        nonce = os.urandom(8).hex()
        mac = hmac.new(self._k, f"{digest}|{nonce}|{via}".encode(), hashlib.sha256).hexdigest()
        return {"digest": digest, "nonce": nonce, "via": via, "mac": mac}
    def consume(self, ap, digest) -> bool:
        if not ap or ap.get("digest") != digest or ap["nonce"] in self._used: return False
        good = hmac.new(self._k, f"{ap['digest']}|{ap['nonce']}|{ap['via']}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, ap["mac"]): return False
        self._used.add(ap["nonce"]); return True

def create_keystore(path, passphrase, kdf="scrypt", iterations=None):
    """Encrypted Web3 Secret Storage v3 keystore. Production default = scrypt; tests pass kdf=pbkdf2 + low iterations for speed."""
    acct = Account.create()
    ks = Account.encrypt(acct.key, passphrase, kdf=kdf, iterations=iterations) if kdf != "scrypt" else Account.encrypt(acct.key, passphrase)
    with open(path, "w") as f: json.dump(ks, f)
    return acct.address

class Signer:
    def __init__(self, keystore_path, passphrase_provider, gate: ApprovalGate, policy_path, recheck=True, scrubber=None):
        with open(keystore_path) as f: self.ks = json.load(f)
        self.pp = passphrase_provider; self.gate = gate
        self.policy_path = policy_path; self.recheck = recheck
        k = Account.decrypt(self.ks, self.pp()); self.address = Account.from_key(k).address  # one-time unlock to learn address
        if scrubber: scrubber.register_secret(k.hex()); scrubber.register_secret(self.pp())
        del k
        self.signed = []   # audit of everything ever signed (decoded)
    def sign(self, tx, approval):
        digest = tx_digest(tx)
        if not self.gate.consume(approval, digest): raise SigningRefused("no valid approval for this exact transaction")
        if self.recheck:
            pol = Policy.load(self.policy_path); dec = decode_tx(tx, pol); res = pol.check(dec, ledger=[], known_recipients=[tx.get("to", "")])
            hard = [x for x in res.reasons if "cap" not in x]   # caps/ledger are enforced by agent with ledger; signer enforces shape+allowlists
            if hard: raise SigningRefused("signer re-check failed: " + "; ".join(hard))
        key = Account.decrypt(self.ks, self.pp())
        try: signed = Account.sign_transaction({k: v for k, v in tx.items() if k != "from"}, key)
        finally: del key
        self.signed.append(decode_tx(tx, Policy.load(self.policy_path)))
        return signed.raw_transaction
