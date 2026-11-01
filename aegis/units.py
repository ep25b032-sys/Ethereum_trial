import re
from decimal import Decimal, InvalidOperation
_AMT = re.compile(r"^\d+(\.\d+)?$")
MAX_UINT = 2**256 - 1
def parse_amount(s, decimals: int):
    """Strict decimal string -> base units. Raises ValueError on anything odd (neg, exp, zero, too precise)."""
    if not isinstance(s, str) or not _AMT.match(s.strip()): raise ValueError(f"bad amount {s!r}")
    d = Decimal(s.strip()) * (Decimal(10) ** decimals)
    if d != d.to_integral_value(): raise ValueError("too many decimals")
    return int(d)
def fmt_amount(v: int, decimals: int) -> str:
    q = Decimal(v) / (Decimal(10) ** decimals)
    return format(q.normalize(), "f") if v else "0"
