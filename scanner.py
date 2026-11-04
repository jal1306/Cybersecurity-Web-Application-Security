"""Low-impact checks for authorized website assessments."""
from urllib.parse import urlparse, urljoin
import socket
import ssl
import requests
from requests.exceptions import RequestException

TIMEOUT = 8
USER_AGENT = "LocalEduSecurityScanner/1.0 (authorized low-impact checks)"
SECURITY_HEADERS = {
    "Content-Security-Policy": ("High", "Helps limit script injection and other content risks."),
    "X-Content-Type-Options": ("Medium", "Set to nosniff to reduce MIME-sniffing risks."),
    "X-Frame-Options": ("Medium", "Helps prevent clickjacking; CSP frame-ancestors is a modern alternative."),
    "Referrer-Policy": ("Low", "Controls how much referrer information browsers send."),
    "Permissions-Policy": ("Low", "Restricts browser features such as camera and microphone."),
}

def finding(severity, title, detail, recommendation):
    return {"severity": severity, "title": title, "detail": detail, "recommendation": recommendation}

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return parsed.geturl().rstrip("/")

def scan_target(raw_url):
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = parsed.hostname
    findings = []
    checks = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=False,
                               verify=True)
    except requests.exceptions.SSLError:
        findings.append(finding("High", "TLS certificate validation failed",
            "The HTTPS request could not validate the certificate chain or hostname.",
            "Install a valid certificate for the hostname and keep the certificate chain current."))
        checks.append({"name": "Main page request", "status": "warning", "detail": "TLS validation failed"})
        return _report(url, host, findings, checks)
    except RequestException as exc:
        raise ValueError(f"Could not fetch target: {exc.__class__.__name__}. Check the URL and connectivity.") from exc

    final_url = response.url
    final_parsed = urlparse(final_url)
    headers = response.headers
    checks.append({"name": "HTTP response", "status": "ok" if response.status_code < 500 else "warning",
                   "detail": f"HTTP {response.status_code}; final URL: {final_url}"})

    if parsed.scheme == "http":
        if final_parsed.scheme == "https":
            checks.append({"name": "HTTPS redirect", "status": "ok", "detail": "HTTP request redirected to HTTPS."})
        else:
            findings.append(finding("High", "HTTPS not enforced",
                "The target was accessed over HTTP and did not redirect to HTTPS.",
                "Enable HTTPS and redirect all HTTP requests to HTTPS."))
            checks.append({"name": "HTTPS redirect", "status": "warning", "detail": "No HTTPS redirect observed."})
    if final_parsed.scheme == "https":
        if "Strict-Transport-Security" not in headers:
            findings.append(finding("Medium", "HSTS header missing",
                "The HTTPS response did not include Strict-Transport-Security.",
                "After confirming HTTPS works across subdomains, add a suitable Strict-Transport-Security policy."))
        checks.append({"name": "TLS", "status": "ok", "detail": "HTTPS request completed with certificate validation."})

    for name, (severity, explanation) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(finding(severity, f"Missing {name}", explanation,
                f"Review and configure the {name} response header for the application."))
    server = headers.get("Server")
    if server:
        findings.append(finding("Info", "Server banner disclosed",
            f"The response includes Server: {server[:160]}",
            "Consider minimizing version and implementation details in public response headers."))

    cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not cookies:
        cookie_header = headers.get("Set-Cookie")
        cookies = [cookie_header] if cookie_header else []
    for cookie in cookies[:20]:
        lower = cookie.lower()
        cname = cookie.split("=", 1)[0][:80]
        if final_parsed.scheme == "https" and "secure" not in lower:
            findings.append(finding("Medium", f"Cookie missing Secure: {cname}",
                "A Set-Cookie value was observed without the Secure attribute.",
                "Add Secure to cookies that should only travel over HTTPS."))
        if "httponly" not in lower:
            findings.append(finding("Low", f"Cookie missing HttpOnly: {cname}",
                "A Set-Cookie value was observed without HttpOnly.",
                "Add HttpOnly to session cookies that do not need JavaScript access."))
        if "samesite" not in lower:
            findings.append(finding("Low", f"Cookie missing SameSite: {cname}",
                "A Set-Cookie value was observed without SameSite.",
                "Set an appropriate SameSite value, commonly Lax, after testing application flows."))

    content_type = headers.get("Content-Type", "").lower()
    if "text/html" in content_type:
        body = response.text[:1_500_000].lower()
        if final_parsed.scheme == "https" and ("http://" in body) and any(x in body for x in ("src=\"http://", "href=\"http://")):
            findings.append(finding("Low", "Possible mixed content references",
                "The returned HTML contains one or more literal HTTP resource references. This is a heuristic, not proof of browser-loaded mixed content.",
                "Update page assets and links to HTTPS or safe relative URLs; verify in browser developer tools."))

    # Probe only a small, fixed set of conventional public files using GET.
    for path in ("/robots.txt", "/.well-known/security.txt", "/sitemap.xml"):
        try:
            r = session.get(urljoin(final_url.rstrip("/") + "/", path.lstrip("/")),
                            timeout=TIMEOUT, allow_redirects=True, verify=True, stream=True)
            status = r.status_code
            r.close()
            checks.append({"name": path, "status": "ok" if status == 200 else "info",
                           "detail": f"HTTP {status}"})
        except RequestException:
            checks.append({"name": path, "status": "info", "detail": "Could not check this path."})

    return _report(final_url, host, findings, checks, status_code=response.status_code)

def _report(url, host, findings, checks, status_code=None):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("Critical", "High", "Medium", "Low", "Info")}
    score = max(0, 100 - counts["Critical"]*30 - counts["High"]*20 - counts["Medium"]*10 - counts["Low"]*4)
    return {"url": url, "host": host, "status_code": status_code, "findings": findings,
            "checks": checks, "counts": counts, "score": score}
