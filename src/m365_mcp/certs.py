import datetime
import os
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def ensure_certificate(directory, days=730):
    """Create the app certificate once in the data volume; the private key never leaves the container."""
    directory = Path(directory)
    pfx, password = directory / 'm365.pfx', directory / 'pfx_password'
    if pfx.exists() and password.exists():
        return str(pfx), str(password)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(32)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'o365-mcp')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days)).sign(key, hashes.SHA256()))
    data = pkcs12.serialize_key_and_certificates(b'o365-mcp', key, cert, None,
                                                 serialization.BestAvailableEncryption(secret.encode()))
    for path, content in ((password, secret.encode()), (pfx, data)):
        tmp = path.with_suffix('.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
        tmp.replace(path)
    return str(pfx), str(password)


def certificate_info(pfx_path, password_path):
    password = Path(password_path).read_bytes().rstrip(b'\r\n')
    _, cert, _ = pkcs12.load_key_and_certificates(Path(pfx_path).read_bytes(), password)
    return {'subject': cert.subject.rfc4514_string(),
            'thumbprint_sha1': cert.fingerprint(hashes.SHA1()).hex().upper(),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'pem': cert.public_bytes(serialization.Encoding.PEM).decode(),
            'notice': 'Public certificate only. Upload the PEM as .cer/.crt in Entra under Certificates & secrets.'}
