import ipaddress, socket, requests
from urllib.parse import urlparse
class WebTool:
    """Fetches only URLs the user typed. Blocks private/loopback hosts (SSRF), caps size, returns text as UNTRUSTED data."""
    def fetch(self, url):
        u = urlparse(url)
        if u.scheme not in ("http", "https"): raise ValueError("scheme")
        ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local: raise ValueError("private host blocked")
        r = requests.get(url, timeout=10, headers={"User-Agent": "aegis-wallet/0.1"}, stream=True)
        return r.raw.read(200_000, decode_content=True).decode("utf8", "replace")
class SimWeb:
    """In-memory web for reproducible tests."""
    def __init__(self, pages): self.pages, self.requests = pages, []
    def fetch(self, url): self.requests.append(url); return self.pages[url]
