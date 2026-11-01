"""Secret scrubber: applied to model inputs, model outputs, outbound requests and logs.
Detects private keys, BIP-39-style seed phrases, registered canary secrets (loaded key, passphrase)."""
import re

_HEX64 = re.compile(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_WORDS = re.compile(r"(?<![A-Za-z])(?:[a-z]{3,8}[\s,]+){11,}[a-z]{3,8}(?![A-Za-z])")
# seed-phrase heuristic needs a real wordlist to avoid redacting prose; use a compact English filter:
_COMMON = set("the a an and or of to in on for with is are was be this that it as by at from your you my me i we they "
              "send transfer pay please approve deposit summarize page read what how why who when where which will would "
              "can could should about into over under all any some then than also not but if so do does did have has had "
              "eth token tokens wallet address amount ignore previous instructions user system".split())

class Scrubber:
    def __init__(self):
        self.secrets = set()      # exact secrets (passphrase, loaded key hex) -> always redacted
        self.public_hashes = set()  # 32-byte values that are public (tx hashes, digests) -> not redacted
        self.hits = 0

    def register_secret(self, s: str):
        if s and len(s) >= 6:
            self.secrets.add(s); self.secrets.add(s.lower())
            if s.startswith("0x"): self.secrets.add(s[2:]); self.secrets.add(s[2:].lower())

    def register_public(self, h: str):
        self.public_hashes.add(h.lower().removeprefix("0x"))

    def scrub(self, text):
        if not isinstance(text, str): return text
        out = text
        for s in sorted(self.secrets, key=len, reverse=True):
            if s in out: out = out.replace(s, "[REDACTED:SECRET]"); self.hits += 1
        def hexsub(m):
            if m.group(0).lower().removeprefix("0x") in self.public_hashes: return m.group(0)
            self.hits += 1; return "[REDACTED:PRIVATE_KEY]"
        out = _HEX64.sub(hexsub, out)
        def seedsub(m):
            run = m.group(0)
            toks = [(t.start(), t.end(), t.group(0)) for t in re.finditer(r"[a-z]{3,8}", run)]
            for size in (24, 21, 18, 15, 12):
                for i in range(0, len(toks) - size + 1):
                    win = toks[i:i + size]
                    if sum(w[2] in _COMMON for w in win) <= 2:
                        self.hits += 1
                        return run[:win[0][0]] + "[REDACTED:SEED_PHRASE]" + run[win[-1][1]:]
            return run
        return _WORDS.sub(seedsub, out)

    def contains_secret(self, text: str) -> bool:
        return self.scrub(text) != text

    def scrub_obj(self, o):
        if isinstance(o, str): return self.scrub(o)
        if isinstance(o, dict): return {k: self.scrub_obj(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)): return [self.scrub_obj(v) for v in o]
        return o
