"""Run locally. Store the displayed bearer token in the MCP client's secret store."""
import hashlib
import secrets

token = secrets.token_urlsafe(48)
print('Bearer token (secret, shown once):', token)
print('token_sha256 (put in tenants.json):', hashlib.sha256(token.encode()).hexdigest())
