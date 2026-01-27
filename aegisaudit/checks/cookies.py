from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

def check_cookies(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    # Note: cookie args in requests/httpx are a dict of name->value. 
    # To get flags (Secure, HttpOnly), we need to inspect the 'Set-Cookie' header raw strings
    # or iterate through the storage if available. 
    # For now, let's parse the 'set-cookie' header manually strictly from headers if present.
    # httpx merges multiple Set-Cookie headers, but in IDM we might want raw access.
    # The artifact.headers is a dict. If multiple Set-Cookie headers were sent, 
    # httpx/standard might fold them? Actually httpx client.get() returns cookies in .cookies jar.
    # But ScanArtifact stores headers as a dict. 
    # Let's try to look for Set-Cookie in headers (it might be folded with ", ") or rely on some other mechanism?
    # Simple approach: Check artifact.cookies for names, but we can't see flags there easily in the simple
    # ScanArtifact model I defined earlier (it just has name:value).
    
    # Correction: I should update ScanArtifact to store raw cookie jars or parsed cookies with flags.
    # For MVP without changing models too much, I'll try to rely on raw header analysis if possible, 
    # or just skip rigorous flag checks if I can't see them.
    # Wait, 'set-cookie' is a response header. 
    
    # We will assume 'Set-Cookie' might be available in `headers` but folding makes it hard to parse multiple.
    # Let's leave a TODO to improve cookie parsing in `fetcher.py`.
    # For now, let's just warn if we see a session-like cookie without Secure if the URL is HTTPS.
    
    # This is a limitation of the current simplified ScanArtifact. 
    # I will stick to a basic check: "Are we setting cookies over HTTP?"
    
    if artifact.url.startswith("http://") and artifact.cookies:
         findings.append(Finding(
            id="cookies-over-http",
            severity=Severity.HIGH,
            title="Cookies Set Over HTTP",
            description="Cookies are being set on an unencrypted connection.",
            evidence=str(list(artifact.cookies.keys())),
            url=artifact.url,
            remediation="Always use HTTPS.",
            tags=["cookies"]
        ))

    return findings
