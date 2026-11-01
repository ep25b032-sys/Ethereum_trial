#!/usr/bin/env python3
"""EDITABLE SOURCE for docs/architecture.svg.  Edit boxes/arrows below, run `python scripts/make_diagram.py`."""
import os, textwrap
W, H = 1200, 800
out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="Helvetica,Arial,sans-serif">',
 '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#333"/></marker>'
 '<marker id="r" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#b00020"/></marker></defs>',
 f'<rect width="{W}" height="{H}" fill="#fff"/>',
 '<text x="20" y="22" font-size="17" font-weight="bold">Aegis Wallet: access layer between an open-source LLM and an Ethereum wallet (everything runs on the user\'s machine)</text>']
def zone(x, y, w, h, title, stroke, dash=False, fill="none"):
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="2"' + (' stroke-dasharray="7 5"' if dash else '') + '/>')
    out.append(f'<text x="{x+10}" y="{y+16}" font-size="12" font-weight="bold" fill="{stroke}">{title}</text>')
def box(x, y, w, h, lines, fill="#f4f6f8", stroke="#555", bold=True):
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
    for i, l in enumerate(lines):
        out.append(f'<text x="{x+w/2}" y="{y+19+i*15}" font-size="{12 if i==0 and bold else 11}" text-anchor="middle"' + (' font-weight="bold"' if i == 0 and bold else '') + f'>{l}</text>')
def arrow(d, label=None, lx=0, ly=0, red=False, dash=False, anchor="start"):
    c = "#b00020" if red else "#333"
    out.append(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="1.8" marker-end="url(#{"r" if red else "a"})"' + (' stroke-dasharray="5 4"' if dash else '') + '/>')
    if label: out.append(f'<text x="{lx}" y="{ly}" font-size="10.5" fill="{c}" text-anchor="{anchor}">{label}</text>')
# zones
zone(10, 36, 230, 700, "USER (trusted channel)", "#1b7f3b")
zone(10, 178, 230, 100, "", "#b00020", True, "#fff5f5"); out.append('<text x="20" y="194" font-size="12" font-weight="bold" fill="#b00020">UNTRUSTED CONTENT (data only)</text>')
zone(260, 36, 300, 280, "MODEL ZONE: proposer only", "#c46a00")
zone(590, 36, 600, 520, "ACCESS LAYER (deterministic code; this is the submission)", "#1f4e9c")
zone(590, 566, 600, 118, "KEY BOUNDARY", "#1b7f3b")
# user zone
box(25, 60, 200, 60, ["You type a request", "(only source of recipient/amount/asset)"], "#e8f5ec", "#1b7f3b")
box(25, 215, 200, 52, ["Web page / document", "/ tool output"], "#fff", "#b00020", bold=False)
box(25, 470, 200, 100, ["Confirmation prompt", "built from DECODED calldata:", "who, what, how much, fee,", "NEW-RECIPIENT warning"], "#e8f5ec", "#1b7f3b")
box(25, 600, 200, 80, ["Out-of-band commands", "/grant /contact /allow-spender", "(edit policy.json; no model path)"], "#e8f5ec", "#1b7f3b")
# model zone
box(275, 60, 270, 50, ["Secret scrubber", "keys, seed phrases, passphrase"], "#fff4e0", "#c46a00")
box(275, 190, 270, 110, ["Open-source LLM (e.g. Ollama)", "sees: your sentence + contact LABELS", "returns ONE JSON proposal", "no keys, no addresses, no balances,", "no signer/chain handle"], "#fff4e0", "#c46a00")
# pipeline
steps = [("1  Strict schema parse", "closed action set; unknown/extra fields (data, gas) rejected"),
         ("2  Grounding + ambiguity", "recipient/amount/asset/verb must appear in YOUR message; else ask or block"),
         ("3  Deterministic tx builder", "layer (not model) encodes calldata; model supplies no bytes"),
         ("4  Decode round-trip + simulate", "raw bytes decoded independently; estimateGas / balance check"),
         ("5  Policy engine", "caps, 24h ledger, allowlists, no unlimited approve, grants"),
         ("6  Approval gate", "one-time token bound to sha256(tx); standing grants scoped")]
for i, (t, d) in enumerate(steps):
    y = 62 + i * 78; box(620, y, 310, 58, [t] + textwrap.wrap(d, 50), "#eaf0fb", "#1f4e9c")
    if i < 5: arrow(f"M775,{y+58} V{y+78}")
box(965, 376, 210, 56, ["policy.json (user-owned)", "caps, contacts, spenders, grants"], "#fffbe0", "#8a7600")
# signer
box(620, 596, 310, 76, ["Signer (only code that touches the key)", "verifies approval == digest(tx); re-checks", "policy from DISK; decrypts key at sign time"], "#e8f5ec", "#1b7f3b")
box(965, 596, 210, 60, ["Encrypted keystore", "(Web3 secret storage v3)"], "#e8f5ec", "#1b7f3b")
box(620, 700, 560, 52, ["Ethereum: local EVM (reproducible) or testnet RPC", "receives only the signed raw tx + read calls; never prompts, policy, or the key"], "#eef", "#336")
# arrows
arrow("M125,120 V135 H260 V85 H275", "message", 150, 131)
arrow("M125,267 V290 H255 V215 H275", "wrapped as untrusted, scrubbed", 30, 304)
arrow("M410,110 V190", "scrubbed text", 418, 155)
arrow("M545,245 H570 V91 H620", "JSON proposal", 548, 262)
arrow("M125,60 V46 H604 V169 H620", "trusted channel: the ONLY grounding source", 300, 33)
arrow("M965,404 H930", None)
arrow("M620,482 H225", "summary from decoded tx", 235, 476)
arrow("M225,502 H620", "user approves exact digest", 235, 518)
arrow("M775,510 V596", "approval token", 785, 556)
arrow("M930,634 H965", "unlock", 934, 628)
arrow("M1040,432 V582 H900 V596", "re-check from disk", 1048, 500, dash=True)
arrow("M775,672 V700", "raw signed tx", 785, 690)
arrow("M125,680 V772 H1195 V404 H1175", "user-only edits", 640, 768, dash=True)
for i, l in enumerate(["Injected text can steer the model but can NOT supply a", "value the signer sees: step 2 trusts only the user's", "own message, so hijacked proposals are blocked."]):
    out.append(f'<text x="270" y="{338+i*14}" font-size="11" fill="#b00020">{l}</text>')
out.append('<text x="270" y="396" font-size="11" font-weight="bold">Information flows (results/privacy_flows.md)</text>')
for i, l in enumerate(["Model: user text, labels, symbols only", "RPC node: signed tx + reads (public by design)", "Web: only URLs the user typed", "Logs: scrubbed. Policy: never leaves disk"]):
    out.append(f'<text x="280" y="{413+i*15}" font-size="10.5">- {l}</text>')
out.append('</svg>')
svg = "\n".join(x for x in out if x)
path = os.path.join(os.path.dirname(__file__), "..", "docs", "architecture.svg")
with open(path, "w") as f: f.write(svg)
print("wrote", path)
