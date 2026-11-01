"""Verifies the Ollama PLUMBING with a fake local server that behaves like a sloppy small LLM (numbers instead of strings, synonyms, extra keys).
This does not test LLM quality; run scripts/check_llm.py for that."""
import json, threading, warnings, tempfile, http.server
warnings.simplefilter("ignore")
from aegis.models import OllamaModel, normalize_proposal
from aegis.agent import Agent
from aegis.evalkit import KS, PASS, ADDRESS
from aegis.chain import local_chain, deploy_env, default_policy
from aegis.signer import Signer, ApprovalGate
from aegis.policy import Policy
from aegis.scrubber import Scrubber

REPLIES = {"send 0.5 eth to alice": {"action": "transfer", "recipient": "alice", "amount": 0.5, "token": "eth", "memo": "hi", "calldata": "0xdead"},
           "who can i send to": {"action": "list_contacts"}, "approve 100 tusd for vault": {"action": "approve", "to": "vault", "amount": 100, "asset": "tusd"}}
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        user = [m for m in body["messages"] if m["role"] == "user"][-1]["content"].lower().strip("? ")
        out = json.dumps(REPLIES.get(user, {"action": "clarify", "question": "?"})).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"message": {"content": out.decode()}}).encode())
    def log_message(self, *a): pass

def test_normalizer():
    assert normalize_proposal({"action": "Transfer", "recipient": "alice", "amount": 1e-05, "token": "ETH", "bogus": 1}) == {"action": "send", "to": "alice", "amount": "0.00001", "asset": "ETH"}

def test_pipeline_with_fake_ollama():
    srv = http.server.HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    chain = local_chain(); env = deploy_env(chain, ADDRESS); d = tempfile.mkdtemp(); pp = d + "/p.json"; Policy(default_policy(env), pp).save()
    sc = Scrubber(); g = ApprovalGate(); sg = Signer(KS, lambda: PASS, g, pp, scrubber=sc)
    class Y:
        def confirm(self, s): return True
    ag = Agent(chain, pp, sg, g, Y(), OllamaModel("fake", f"http://127.0.0.1:{srv.server_port}"), scrubber=sc)
    assert ag.handle("send 0.5 ETH to alice").status == "executed"       # sloppy output normalised, still fully validated
    assert "alice" in ag.handle("who can I send to?").message
    assert ag.handle("approve 100 tUSD for vault").status == "executed"
    srv.shutdown()

def test_model_down_fails_safe():
    chain = local_chain(); env = deploy_env(chain, ADDRESS); d = tempfile.mkdtemp(); pp = d + "/p.json"; Policy(default_policy(env), pp).save()
    sc = Scrubber(); g = ApprovalGate(); sg = Signer(KS, lambda: PASS, g, pp)
    ag = Agent(chain, pp, sg, g, None, OllamaModel("x", "http://127.0.0.1:9"), scrubber=sc)
    r = ag.handle("send 0.5 ETH to alice"); assert r.status == "blocked" and "Ollama" in r.message
