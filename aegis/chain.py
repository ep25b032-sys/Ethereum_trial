"""Reproducible local chain (eth-tester/py-evm, in-process) or any JSON-RPC endpoint (Anvil/Sepolia)."""
import json, os
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from eth_account import Account
BUILD = os.path.join(os.path.dirname(__file__), "..", "build", "contracts.json")

class RecordingProvider(EthereumTesterProvider):
    """Records every JSON-RPC call = exactly what the RPC node operator sees."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k); self.calls = []
    def make_request(self, method, params):
        self.calls.append({"method": method, "params": json.loads(json.dumps(params, default=str))})
        return super().make_request(method, params)

class Chain:
    def __init__(self, w3, recorder=None):
        self.w3, self.recorder = w3, recorder
    @property
    def rpc_log(self): return self.recorder.calls if self.recorder else []

def local_chain():
    prov = RecordingProvider()
    w3 = Web3(prov)
    return Chain(w3, prov)

def deploy_env(chain: Chain, user_addr: str, funded_eth=10, token_supply=10_000 * 10**6):
    """Fund the user's address, deploy TestToken (tUSD) + Vault. Returns dict of addresses."""
    w3 = chain.w3
    with open(BUILD) as f: art = json.load(f)
    root = w3.eth.accounts[0]
    w3.eth.wait_for_transaction_receipt(w3.eth.send_transaction({"from": root, "to": user_addr, "value": funded_eth * 10**18}))
    def dep(name, *args):
        c = w3.eth.contract(abi=art[name]["abi"], bytecode=art[name]["bytecode"])
        h = c.constructor(*args).transact({"from": root})
        return w3.eth.wait_for_transaction_receipt(h).contractAddress
    token = dep("TestToken", user_addr, token_supply)
    vault = dep("Vault")
    return {"token": token, "vault": vault, "alice": w3.eth.accounts[1], "bob": w3.eth.accounts[2], "attacker": w3.eth.accounts[9],
            "chain_id": w3.eth.chain_id, "abi": {k: v["abi"] for k, v in art.items()}}

def default_policy(env):
    return {
        "chain_id": env["chain_id"],
        "allowed_actions": ["eth_transfer", "erc20_transfer", "erc20_approve", "vault_deposit"],
        "tokens": {"tUSD": {"address": env["token"], "decimals": 6}},
        "contacts": {"alice": env["alice"], "bob": env["bob"]},
        "spenders": {"vault": env["vault"]},
        "caps": {"ETH": {"per_tx": "1", "daily": "2"}, "tUSD": {"per_tx": "500", "daily": "1000"}},
        "approve_cap": {"tUSD": "500"},
        "max_fee_eth": "0.01",
        "grants": [],
    }
