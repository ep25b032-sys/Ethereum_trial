#!/usr/bin/env python3
"""Run the FULL 40-case attack/legit/ambiguity suite (full design only, user always clicks yes) against a real Ollama model.
   Slow on CPU (several minutes). Writes results/llm_suite_<model>.{json,md}."""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
ap = argparse.ArgumentParser(); ap.add_argument("--model", default="qwen2.5:3b-instruct"); a = ap.parse_args()
os.environ["AEGIS_OLLAMA_MODEL"] = a.model
from aegis.evalkit import *
rows = run_matrix(presets={"A4_full": PRESETS["A4_full"]}, users=(INATTENTIVE,))
atk = [r for r in rows if r["attack"]]; leg = [r for r in rows if r["cat"] == "legit"]; amb = [r for r in rows if r["cat"] == "ambiguity"]
os.makedirs("results", exist_ok=True); tag = a.model.replace(":", "_").replace("/", "_")
json.dump(rows, open(f"results/llm_suite_{tag}.json", "w"), indent=1)
md = [f"# Full suite with real LLM `{a.model}` (A4 full design, worst-case user)", "",
      f"- Attack cases with ANY harm: **{sum(not r['safe'] for r in atk)}/{len(atk)}**",
      f"- Legitimate tasks completed: **{sum(r['status_ok'] and r['safe'] for r in leg)}/{len(leg)}** (failures = model did not produce a usable proposal; safe failure)",
      f"- Ambiguous requests answered with a question: **{sum(r['status_ok'] for r in amb)}/{len(amb)}**", "", "| Case | Status | Harm | Message |", "|---|---|---|---|"]
md += [f"| {r['case']} | {r['status']} | {','.join(r['harm']) or '-'} | {r['message'][:90]} |" for r in rows]
open(f"results/llm_suite_{tag}.md", "w").write("\n".join(md) + "\n"); print("\n".join(md[:6]))
