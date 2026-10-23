from datetime import datetime
from urllib.parse import urlparse
import ipaddress
import socket
import requests

TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 5
USER_AGENT = "StudentWebSecurityScanner/1.0 (authorized security checks only)"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps browsers enforce HTTPS.",
    "Content-Security-Policy": "Restricts which sources can load content.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risk.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Restricts use of browser features."
}

def _is_public_host(hostname):
    """Reject obvious local/private targets to reduce accidental unsafe scans."""
    if not hostname:
        return False
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for item in addresses:
        address = ipaddress.ip_address(item[4][0].split("%")[0])
        if not address.is_global:
            return False
    return bool(addresses)

def normalize_and_validate_url(raw_url):
    if not raw_url:
        raise ValueError("Enter a URL such as https://example.com.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL does not contain a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not allowed.")
    if not _is_public_host(parsed.hostname):
        raise ValueError("The hostname could not be resolved to a public IP address. Local and private targets are not scanned.")
    return raw_url

def scan_url(raw_url):
    target = normalize_and_validate_url(raw_url)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(
            target,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=True,
            stream=True
        )
    except requests.RequestException as exc:
        raise ValueError("Request failed: " + str(exc)) from exc

    try:
        final_url = response.url
        headers = response.headers
        final_parsed = urlparse(final_url)
        checks = []

        is_https = final_parsed.scheme == "https"
        checks.append({
            "name": "HTTPS",
            "status": "PASS" if is_https else "WARN",
            "details": "Final URL uses HTTPS." if is_https else "Final URL is HTTP. Use HTTPS to protect data in transit."
        })

        for header, purpose in SECURITY_HEADERS.items():
            present = header in headers
            status = "PASS" if present else "WARN"
            details = (f"Header is present. {purpose}" if present
                       else f"Header is missing. {purpose}")
            if header == "Strict-Transport-Security" and not is_https:
                status = "INFO"
                details = "HSTS is relevant for HTTPS sites; this target ended on HTTP."
            checks.append({"name": header, "status": status, "details": details})

        cors = headers.get("Access-Control-Allow-Origin")
        if cors is None:
            checks.append({
                "name": "CORS configuration",
                "status": "INFO",
                "details": "No Access-Control-Allow-Origin header was returned on this response. This alone does not prove CORS is secure or insecure."
            })
        elif cors.strip() == "*":
            credentials = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if credentials:
                status = "WARN"
                details = "Wildcard origin and credential permission were both observed. Verify the server's CORS behavior and browser enforcement."
            else:
                status = "INFO"
                details = "Wildcard origin was observed. This can be appropriate for public, non-credentialed resources; review whether it is intended."
            checks.append({"name": "CORS configuration", "status": status, "details": details})
        else:
            checks.append({
                "name": "CORS configuration",
                "status": "INFO",
                "details": f"Access-Control-Allow-Origin is set to {cors!r}. Confirm that only intended origins are trusted."
            })

        server = headers.get("Server")
        checks.append({
            "name": "Server banner",
            "status": "INFO" if server else "PASS",
            "details": f"Server header discloses: {server}" if server else "No Server header was disclosed in this response."
        })

        return {
            "target": final_url,
            "scanned_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
            "status_code": response.status_code,
            "checks": checks,
            "note": "This is a basic configuration check, not a penetration test. Results can be incomplete or context-dependent."
        }
    finally:
        response.close()
        session.close()
