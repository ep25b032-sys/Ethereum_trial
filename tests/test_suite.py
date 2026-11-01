"""The attack/legit/ambiguity matrix. A4_full must be SAFE for every case even with a worst-case user who clicks 'yes' to everything."""
import pytest
from aegis.evalkit import CASES, PRESETS, run_case, run_matrix, summarize, INATTENTIVE, ATTENTIVE

@pytest.mark.parametrize("user", [INATTENTIVE, ATTENTIVE])
@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_full_design(case, user):
    r = run_case(case, PRESETS["A4_full"], user, "A4_full")
    assert r["safe"], f"HARM {r['harm']}: {r['message']}"
    assert r["status_ok"], f"status {r['status']} not in {case.ok}: {r['message']}"

def test_ablation_is_monotone_and_full_design_is_zero():
    S = summarize(run_matrix(users=(INATTENTIVE,)))
    asr = [S[(t, INATTENTIVE)]["attack_success"] for t in PRESETS]
    assert asr == sorted(asr, reverse=True) and asr[-1] == 0 and asr[0] > 0
