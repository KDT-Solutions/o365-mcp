import asyncio
import json
import uuid
from pathlib import Path

import httpx
import msal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


class Graph:
    def __init__(self, client_id, pfx_path, password_path):
        password = Path(password_path).read_bytes().rstrip(b'\r\n')
        key, cert, _ = load_key_and_certificates(Path(pfx_path).read_bytes(), password)
        if key is None or cert is None:
            raise ValueError('PFX requires private key and certificate')
        self.credential = {
            'private_key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'thumbprint': cert.fingerprint(hashes.SHA1()).hex(),
        }
        self.client_id = client_id
        self.apps = {}

    def token(self, tenant):
        if tenant.tenant_id not in self.apps:
            self.apps[tenant.tenant_id] = msal.ConfidentialClientApplication(
                self.client_id, authority=f'https://login.microsoftonline.com/{tenant.tenant_id}',
                client_credential=self.credential)
        app = self.apps[tenant.tenant_id]
        result = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
        if 'access_token' not in result:
            raise RuntimeError('Microsoft authentication failed; check tenant consent and certificate')
        return result['access_token']

    async def request(self, tenant, path, params=None, body=None, method=None):
        token = await asyncio.to_thread(self.token, tenant)
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            for attempt in range(4):
                response = await client.request(method or ('PATCH' if body is not None else 'GET'),
                    'https://graph.microsoft.com/v1.0/' + path,
                    headers={'Authorization': 'Bearer ' + token}, params=params, json=body)
                if response.status_code in (429, 502, 503, 504) and attempt < 3:
                    delay = response.headers.get('Retry-After', '')
                    await asyncio.sleep(min(int(delay), 30) if delay.isdigit() else 2 ** attempt)
                    continue
                if response.is_error:
                    raise RuntimeError(f'Graph HTTP {response.status_code}; request-id={response.headers.get("request-id", "unknown")}')
                return response.json() if response.content else {'success': True}

    async def listing(self, tenant, resource, select, limit=100):
        if type(limit) is not int or not 1 <= limit <= 999:
            raise ValueError('limit must be between 1 and 999')
        data = await self.request(tenant, resource, {'$select': select, '$top': str(limit)})
        # Never expose or fetch arbitrary continuation URLs supplied by callers.
        return {'items': data.get('value', []), 'more_available': '@odata.nextLink' in data,
                'notice': 'Bounded first page. Narrow administrative queries before changing objects.'}

    async def block(self, tenant, target):
        target = str(uuid.UUID(target))
        return await self.request(tenant, f'users/{target}', body={'accountEnabled': False})

    async def admin_change(self, tenant, action, target, payload):
        target = str(uuid.UUID(target))
        if action == 'assign_licenses':
            return await self.request(tenant, f'users/{target}/assignLicense', body=payload, method='POST')
        if action == 'revoke_sessions':
            return await self.request(tenant, f'users/{target}/revokeSignInSessions', body={}, method='POST')
        if action == 'add_group_member':
            member = str(uuid.UUID(payload['member_id']))
            return await self.request(tenant, f'groups/{target}/members/$ref',
                body={'@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{member}'}, method='POST')
        if action == 'remove_group_member':
            member = str(uuid.UUID(payload['member_id']))
            # The /$ref suffix is essential: delete only membership, never the directory object.
            return await self.request(tenant, f'groups/{target}/members/{member}/$ref', method='DELETE')
        raise ValueError('Unsupported Graph operation')


class Exchange:
    def __init__(self, client_id, pfx_path, password_path, script):
        self.client_id, self.pfx_path, self.password_path, self.script = client_id, pfx_path, password_path, script
        self.lock = asyncio.Semaphore(2)

    async def run(self, tenant, action, target=''):
        if action not in ('list_mailboxes', 'get_mailbox', 'convert_shared'):
            raise ValueError('Unsupported Exchange operation')
        if target:
            target = str(uuid.UUID(target))
        payload = json.dumps({'client_id': self.client_id, 'organization': tenant.organization,
                              'certificate': self.pfx_path, 'password_file': self.password_path,
                              'action': action, 'target': target}).encode()
        async with self.lock:
            proc = await asyncio.create_subprocess_exec('pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', self.script,
                                                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(payload), timeout=180)
            except (TimeoutError, asyncio.CancelledError):
                proc.kill()
                await proc.wait()
                raise RuntimeError('Exchange execution interrupted; verify remote state before retrying') from None
        if proc.returncode:
            raise RuntimeError('Exchange command failed; verify consent, RBAC and target. Remote state may have changed.')
        try:
            return json.loads(stdout)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError('Invalid Exchange response; verify remote state before retrying') from None
