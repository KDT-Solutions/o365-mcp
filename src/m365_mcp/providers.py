import asyncio
import base64
import json
import re
import time
import uuid
from pathlib import Path

import httpx
import msal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')
MAILBOX_RIGHTS = ('full_access', 'send_as', 'calendar')
CALENDAR_ROLES = ('Reviewer', 'Author', 'Editor')


def mailbox_reference(value):
    """Entra object UUID or SMTP address of a mailbox; anything else is rejected."""
    value = (value or '').strip()
    try:
        return {'target': str(uuid.UUID(value))}
    except ValueError:
        pass
    if len(value) > 254 or not EMAIL.fullmatch(value):
        raise ValueError('Mailbox must be an Entra object UUID or an SMTP address')
    return {'mailbox': value.lower()}


DOMAIN = re.compile(r'(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
ISSUER = re.compile(r'https://login\.microsoftonline\.com/([0-9a-f-]{36})/v2\.0')


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
        # Short-lived per-user OneDrive inventories (10 minutes) for repeated searches.
        self.inventories = {}

    def token(self, tenant):
        if not self.client_id:
            raise RuntimeError('Entra app client_id is not configured')
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

    async def request_link(self, tenant, link):
        """Follow a Graph paging link (@odata.nextLink) returned by Graph itself; any other host or API version is refused."""
        prefix = 'https://graph.microsoft.com/v1.0/'
        if not isinstance(link, str) or not link.startswith(prefix):
            raise ValueError('Unexpected paging link')
        return await self.request(tenant, link[len(prefix):])

    async def drive_inventory(self, tenant, user_id, max_items=50000):
        """All items of a user's OneDrive as a flat list via the delta query (works with app-only access)."""
        user_id = str(uuid.UUID(user_id))
        key = (tenant.tenant_id, user_id)
        cached = self.inventories.get(key)
        if cached and time.monotonic() - cached[0] < 600:
            return cached[1], cached[2]
        data = await self.request(tenant, f'users/{user_id}/drive/root/delta',
                                  {'$select': 'id,name,size,createdDateTime,lastModifiedDateTime,file,folder,parentReference,deleted'})
        items, complete = [], True
        while True:
            items.extend(i for i in data.get('value', []) if 'deleted' not in i)
            link = data.get('@odata.nextLink')
            if not link:
                break
            if len(items) >= max_items:
                complete = False
                break
            data = await self.request_link(tenant, link)
        self.inventories[key] = (time.monotonic(), items, complete)
        return items, complete

    async def listing(self, tenant, resource, select, limit=100):
        if type(limit) is not int or not 1 <= limit <= 999:
            raise ValueError('limit must be between 1 and 999')
        data = await self.request(tenant, resource, {'$select': select, '$top': str(limit)})
        # Never expose or fetch arbitrary continuation URLs supplied by callers.
        return {'items': data.get('value', []), 'more_available': '@odata.nextLink' in data,
                'notice': 'Bounded first page. Narrow administrative queries before changing objects.'}

    async def granted_roles(self, tenant):
        """Application permissions (role names only) in the current access token for this tenant."""
        token = await asyncio.to_thread(self.token, tenant)
        payload = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        return sorted(str(role) for role in claims.get('roles', []))

    async def resolve_tenant(self, domain):
        """Look up the tenant ID of a verified customer domain via the public OpenID metadata. No credentials are sent."""
        domain = domain.strip().lower()
        if not DOMAIN.fullmatch(domain):
            raise ValueError('Provide a plain domain such as example.com')
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.get(f'https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration')
        if response.status_code in (400, 404):
            raise ValueError('No Microsoft Entra tenant found for this domain')
        if response.is_error:
            raise RuntimeError(f'Tenant lookup failed with HTTP {response.status_code}')
        match = ISSUER.fullmatch(response.json().get('issuer', ''))
        if not match:
            raise RuntimeError('Unexpected tenant metadata')
        return str(uuid.UUID(match.group(1)))

    async def organization(self, tenant):
        data = await self.request(tenant, 'organization', {'$select': 'id,displayName,verifiedDomains'})
        items = data.get('value', [])
        if len(items) != 1:
            raise RuntimeError('Unexpected organization response')
        return items[0]

    async def share_file(self, tenant, payload):
        """Grant a user access to one drive item without sending an invitation e-mail."""
        owner = str(uuid.UUID(payload['owner']))
        item_id, recipient, role = payload['item_id'], payload['recipient'], payload['role']
        if not re.fullmatch(r'[A-Za-z0-9!_-]{1,128}', item_id) or not EMAIL.fullmatch(recipient) or role not in ('read', 'write'):
            raise ValueError('Invalid share request')
        result = await self.request(tenant, f'users/{owner}/drive/items/{item_id}/invite', method='POST', body={
            'recipients': [{'email': recipient}], 'requireSignIn': True, 'sendInvitation': False, 'roles': [role]})
        return {'shared_with': recipient, 'role': role, 'permissions': len(result.get('value', []))}

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


def validate_permission(payload):
    """Strictly re-validate a stored permission change before it reaches PowerShell."""
    right, trustee, add = payload.get('right'), payload.get('trustee'), payload.get('add')
    if right not in MAILBOX_RIGHTS or type(add) is not bool or not EMAIL.fullmatch(trustee or ''):
        raise ValueError('Invalid mailbox permission change')
    result = {'right': right, 'trustee': trustee, 'add': add, 'automapping': payload.get('automapping') is True}
    if payload.get('folder'):
        if right != 'calendar':
            raise ValueError('A folder applies to calendar permissions only')
        result['folder'] = validate_folder(payload['folder'])
    if right == 'calendar' and add:
        if payload.get('role') not in CALENDAR_ROLES:
            raise ValueError('Calendar role must be Reviewer, Author or Editor')
        result['role'] = payload['role']
    return result


QUERY = re.compile(r'[\w .-]{3,64}')
FOLDER = re.compile(r'/[^:\\\x00-\x1f]{1,250}')


def validate_folder(path):
    if not isinstance(path, str) or not FOLDER.fullmatch(path):
        raise ValueError('Folder path must look like /Kalender/Name (from find_calendar_folders)')
    return path


def validate_member(payload):
    member, add = payload.get('member'), payload.get('add')
    if type(add) is not bool or not EMAIL.fullmatch(member or ''):
        raise ValueError('Invalid distribution list change')
    return {'member': member, 'add': add}


class ExchangeError(RuntimeError):
    """Exchange rejected a command; the message contains only the exception type, never customer data."""


MARKER = b'@@M365@@'


class Session:
    """One long-lived pwsh process connected to a single customer organization."""

    def __init__(self, proc):
        self.proc = proc
        self.lock = asyncio.Lock()
        self.users = 0
        self.started = self.used = time.monotonic()

    async def receive(self):
        # Ignore anything the Exchange module prints itself; only marked lines are protocol.
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                raise RuntimeError('Exchange session ended unexpectedly')
            if line.startswith(MARKER):
                return json.loads(line[len(MARKER):])

    async def close(self):
        if self.proc.returncode is None:
            try:
                self.proc.stdin.close()
                await asyncio.wait_for(self.proc.wait(), timeout=15)
            except (TimeoutError, ConnectionError, OSError):
                self.proc.kill()
                await self.proc.wait()


class Exchange:
    """Reuses Exchange Online sessions per tenant instead of connecting for every call."""

    def __init__(self, client_id, pfx_path, password_path, script, max_sessions=2, idle_seconds=600, max_age_seconds=2700):
        self.client_id, self.pfx_path, self.password_path, self.script = client_id, pfx_path, password_path, script
        self.max_sessions, self.idle_seconds, self.max_age_seconds = max_sessions, idle_seconds, max_age_seconds
        self.slots = asyncio.Semaphore(max_sessions)
        self.sessions = {}
        self.pool = asyncio.Lock()
        self.reaper = None

    async def start(self, tenant):
        proc = await asyncio.create_subprocess_exec('pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', self.script,
                                                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL, limit=16 * 1024 * 1024)
        session = Session(proc)
        proc.stdin.write(json.dumps({'client_id': self.client_id, 'organization': tenant.organization,
                                     'certificate': self.pfx_path, 'password_file': self.password_path}).encode() + b'\n')
        try:
            await proc.stdin.drain()
            ready = await asyncio.wait_for(session.receive(), timeout=120)
        except BaseException:
            proc.kill()
            await proc.wait()
            raise RuntimeError('Exchange connection failed; verify consent, RBAC and certificate') from None
        if not ready.get('ok'):
            await session.close()
            raise RuntimeError('Exchange connection failed; verify consent, RBAC and certificate')
        return session

    async def discard(self, key):
        session = self.sessions.pop(key, None)
        if session:
            await session.close()

    async def reap(self):
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            async with self.pool:
                for key, session in list(self.sessions.items()):
                    if not session.users and (now - session.used > self.idle_seconds or now - session.started > self.max_age_seconds):
                        await self.discard(key)

    async def session(self, tenant):
        key = tenant.tenant_id
        current = self.sessions.get(key)
        if current and (current.proc.returncode is not None or time.monotonic() - current.started > self.max_age_seconds) and not current.users:
            await self.discard(key)
            current = None
        if current:
            return current
        idle = [k for k, s in self.sessions.items() if not s.users]
        while len(self.sessions) >= self.max_sessions and idle:
            oldest = min(idle, key=lambda k: self.sessions[k].used)
            idle.remove(oldest)
            await self.discard(oldest)
        self.sessions[key] = await self.start(tenant)
        return self.sessions[key]

    async def run(self, tenant, action, target='', extra=None):
        if action not in ('list_mailboxes', 'get_mailbox', 'convert_shared', 'mailbox_permissions', 'set_mailbox_permission',
                          'set_distribution_member', 'find_calendar_folders'):
            raise ValueError('Unsupported Exchange operation')
        if not self.client_id:
            raise RuntimeError('Entra app client_id is not configured')
        request = {'action': action, 'target': ''}
        if target:
            request.update(mailbox_reference(target))
        if action == 'set_distribution_member':
            request.update(validate_member(extra or {}))
        elif action == 'find_calendar_folders':
            query = (extra or {}).get('query', '')
            if not QUERY.fullmatch(query):
                raise ValueError('Search text: 3-64 letters, digits, spaces, dots, hyphens or underscores')
            request['query'] = query
        elif action == 'mailbox_permissions':
            if extra and extra.get('folder'):
                request['folder'] = validate_folder(extra['folder'])
        elif extra:
            request.update(validate_permission(extra))
        if self.reaper is None or self.reaper.done():
            self.reaper = asyncio.create_task(self.reap())
        async with self.slots:
            async with self.pool:
                session = await self.session(tenant)
                session.users += 1
            try:
                return await self.call(session, tenant, request, 900 if action == 'find_calendar_folders' else 180)
            finally:
                session.users -= 1

    async def call(self, session, tenant, request, timeout=180):
        async with session.lock:
            session.used = time.monotonic()
            try:
                session.proc.stdin.write(json.dumps(request).encode() + b'\n')
                await session.proc.stdin.drain()
                reply = await asyncio.wait_for(session.receive(), timeout=timeout)
            except BaseException:
                # State of the remote call is unknown; never reuse this process.
                if session.proc.returncode is None:
                    session.proc.kill()
                    await session.proc.wait()
                if self.sessions.get(tenant.tenant_id) is session:
                    del self.sessions[tenant.tenant_id]
                raise RuntimeError('Exchange execution interrupted; verify remote state before retrying') from None
            session.used = time.monotonic()
        if not reply.get('ok'):
            reason = reply.get('reason') if re.fullmatch(r'[A-Za-z ]{1,80}', str(reply.get('reason', ''))) else 'unknown'
            raise ExchangeError(f'Exchange command failed ({reason}); verify consent, RBAC and target. Remote state may have changed.')
        return reply.get('result')
