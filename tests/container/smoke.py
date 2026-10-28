"""Run inside the production image; only ephemeral, self-generated test credentials."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

pwsh = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command',
    "Import-Module ExchangeOnlineManagement -ErrorAction Stop; "
    "if (-not (Get-Command Connect-ExchangeOnline -ErrorAction Stop)) { exit 1 }; "
    "$e = $null; $t = $null; [System.Management.Automation.Language.Parser]::ParseFile('/app/scripts/exchange.ps1', [ref]$t, [ref]$e) | Out-Null; if ($e.Count) { exit 1 }; "
    "(Get-Module ExchangeOnlineManagement).Version.ToString()"], capture_output=True, text=True)
assert pwsh.returncode == 0, pwsh.stderr
print('Exchange module imported; PowerShell script syntax valid; EXO version:', pwsh.stdout.strip())
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    token = secrets.token_urlsafe(48)
    password = secrets.token_urlsafe(32)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ephemeral-container-test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (root / 'test.pfx').write_bytes(pkcs12.serialize_key_and_certificates(b'test', key, cert, None, serialization.BestAvailableEncryption(password.encode())))
    (root / 'password').write_text(password)
    (root / 'config.json').write_text(json.dumps({
        'client_id': '00000000-0000-0000-0000-000000000001',
        'tenants': [{'alias': 'test', 'tenant_id': '00000000-0000-0000-0000-000000000002', 'organization': 'test.onmicrosoft.com'}],
        'clients': [{'name': 'test', 'token_sha256': hashlib.sha256(token.encode()).hexdigest(), 'tenants': ['test']}] }))
    env = dict(os.environ, CONFIG_PATH=str(root / 'config.json'), CERTIFICATE_PATH=str(root / 'test.pfx'),
               CERTIFICATE_PASSWORD_FILE=str(root / 'password'), STATE_PATH='/data/test.db')
    proc = subprocess.Popen(['m365-mcp'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=1) as response:
                    assert response.status == 200
                break
            except urllib.error.URLError:
                if proc.poll() is not None:
                    raise AssertionError(proc.communicate()[1].decode())
                time.sleep(0.1)
        else:
            raise AssertionError('Service did not start')
        try:
            urllib.request.urlopen('http://127.0.0.1:8000/mcp', timeout=2)
            raise AssertionError('Anonymous MCP request accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        request = urllib.request.Request('http://127.0.0.1:8000/mcp', data=json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'smoke', 'version': '1'}}}).encode(),
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
        with urllib.request.urlopen(request, timeout=5) as response:
            assert 'serverInfo' in json.load(response)['result']
        print('Non-root read-only container: certificate load, startup, health, unauthorized rejection and MCP initialization passed')
    finally:
        proc.terminate()
        proc.communicate(timeout=10)
