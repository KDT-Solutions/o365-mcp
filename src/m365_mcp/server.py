import contextvars
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Mount, Route
import uvicorn

from .certs import certificate_info, ensure_certificate
from .core import ALIAS, Registry, Store, Tenant
from .providers import ExchangeError, CALENDAR_ROLES, MAILBOX_RIGHTS, Exchange, Graph, mailbox_reference, validate_folder

actor = contextvars.ContextVar('actor')
FILE_QUERY = re.compile(r'[\w .-]{2,64}')
ITEM_ID = re.compile(r'[A-Za-z0-9!_-]{1,128}')
DRIVE_PATH = re.compile(r'[\w .-]{1,100}(/[\w .-]{1,100}){0,9}')
PUBLIC_PATHS = ('/healthz', '/consent-done')
# Static page after Microsoft admin consent. Query parameters are deliberately ignored:
# nothing from the callback is trusted, reflected or stored.
CONSENT_PAGE = '''<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zustimmung</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5}</style></head>
<body><h1>Zustimmung abgeschlossen</h1><p>Dieses Fenster kann geschlossen werden. Den Kunden anschliessend im MCP mit
<code>verify_tenant</code> prüfen. Ob die Zustimmung wirklich erteilt wurde, zeigt erst diese Prüfung.</p></body></html>'''


class Authentication:
    def __init__(self, app, registry):
        self.app, self.registry = app, registry

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] in PUBLIC_PATHS:
            return await self.app(scope, receive, send)
        header = dict(scope['headers']).get(b'authorization', b'').decode('latin1')
        client = self.registry.authenticate(header[7:]) if header.startswith('Bearer ') else None
        if client is None:
            return await JSONResponse({'error': 'unauthorized'}, status_code=401)(scope, receive, send)
        marker = actor.set(client)
        try:
            await self.app(scope, receive, send)
        finally:
            actor.reset(marker)


def load_registry(config_path=None):
    if config_path is None and os.environ.get('TENANTS_JSON'):
        return Registry(text=os.environ['TENANTS_JSON'])
    return Registry(config_path or os.environ.get('CONFIG_PATH', '/config/tenants.json'))


def version_info():
    try:
        current = os.environ.get('APP_VERSION') or package_version('m365-cloud-mcp')
    except PackageNotFoundError:
        current = 'unknown'
    return {'name': 'o365-mcp', 'version': current, 'commit': os.environ.get('APP_COMMIT', 'unknown'),
            'built': os.environ.get('APP_BUILD_DATE', 'unknown')}


def create_app(config_path=None, state_path=None, graph=None, exchange=None):
    registry = load_registry(config_path)
    state_path = state_path or os.environ.get('STATE_PATH', '/data/state.db')
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    store = Store(state_path, int(os.environ.get('AUDIT_RETENTION_DAYS', '365')))
    registry.load(*store.tenants())
    consent_redirect = os.environ.get('CONSENT_REDIRECT_URI', '')
    pfx = os.environ.get('CERTIFICATE_PATH', '')
    password = os.environ.get('CERTIFICATE_PASSWORD_FILE', '')
    if not (pfx and Path(pfx).exists()):
        pfx, password = ensure_certificate(os.environ.get('CERTIFICATE_DIR', str(Path(state_path).parent / 'certificate')))
    graph = graph or Graph(registry.client_id, pfx, password)
    exchange = exchange or Exchange(registry.client_id, pfx, password, os.environ.get('EXCHANGE_SCRIPT', '/app/scripts/exchange.ps1'),
                                    max_sessions=int(os.environ.get('EXCHANGE_MAX_SESSIONS', '2')),
                                    idle_seconds=int(os.environ.get('EXCHANGE_IDLE_SECONDS', '600')))
    allowed_hosts = os.environ.get('ALLOWED_HOSTS', 'localhost:*,127.0.0.1:*').split(',')
    mcp = FastMCP('Microsoft 365 Customer Administration', stateless_http=True, json_response=True,
                  streamable_http_path=os.environ.get('MCP_PATH', '/mcp'),
                  transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                      allowed_hosts=allowed_hosts, allowed_origins=os.environ.get('ALLOWED_ORIGINS', '').split(',') if os.environ.get('ALLOWED_ORIGINS') else []))

    def authorize(alias, write=False, pending=False):
        return registry.authorize(actor.get(), alias, write, pending)

    async def read(alias, action, operation, target=''):
        tenant = authorize(alias)
        name = actor.get()['name']
        started = time.monotonic()
        try:
            result = await operation(tenant)
        except Exception as error:
            store.audit(name, alias, action, target, 'failed', elapsed(started))
            if isinstance(error, ExchangeError) or str(error).startswith('Graph HTTP '):
                # Both carry only a status code or exception type and a request id, never response content.
                raise RuntimeError(str(error)) from None
            raise RuntimeError('Provider operation failed. Check tenant permissions and service configuration.') from None
        store.audit(name, alias, action, target, 'succeeded', elapsed(started))
        return result

    def elapsed(started):
        return int((time.monotonic() - started) * 1000)

    @mcp.tool(annotations={'readOnlyHint': True, 'openWorldHint': False})
    def get_version() -> dict:
        """Version and build commit of this MCP server."""
        return version_info()

    @mcp.tool(annotations={'readOnlyHint': True, 'openWorldHint': False})
    def get_app_certificate() -> dict:
        """Public certificate of the Entra app (PEM, SHA-1 thumbprint, validity). Upload it in Entra under Certificates & secrets. The private key never leaves the server."""
        info = certificate_info(pfx, password)
        info['client_id_configured'] = registry.client_id is not None
        return info

    @mcp.tool(annotations={'readOnlyHint': True, 'openWorldHint': False})
    def get_audit_log(tenant: str | None = None, action: str | None = None, hours: int | None = None, limit: int = 100) -> list[dict]:
        """Read the audit log (newest first) for tenants this client may access. Optional filters: tenant alias, action, last N hours. limit 1-1000."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('limit must be between 1 and 1000')
        tenants = [authorize(tenant, pending=True).alias] if tenant else sorted(registry.allowed(actor.get()))
        since = time.time() - hours * 3600 if hours else None
        return store.audit_log(tenants, limit, action, since)

    @mcp.tool(annotations={'readOnlyHint': True, 'openWorldHint': False})
    def list_tenants() -> list[dict]:
        """List customer aliases authorized for the authenticated MCP client."""
        allowed = registry.allowed(actor.get())
        return [{'alias': t.alias, 'tenant_id': t.tenant_id, 'organization': t.organization or None, 'status': t.status,
                 'source': 'mcp' if t.managed else 'config', 'writes_enabled': t.writes and actor.get().get('can_write', False)}
                for t in sorted(registry.tenants.values(), key=lambda t: t.alias) if t.alias in allowed]

    def consent_link(tenant):
        if not registry.client_id:
            raise ValueError('Entra app client_id is not configured')
        params = {'client_id': registry.client_id}
        if consent_redirect:
            params['redirect_uri'] = consent_redirect
        return f'https://login.microsoftonline.com/{tenant.tenant_id}/adminconsent?' + urlencode(params)

    def consent_steps(tenant):
        return {'consent_url': consent_link(tenant),
                'next_steps': ['Open consent_url and sign in with your admin account of exactly this customer tenant; accept the permissions.',
                               'Run verify_tenant with this alias. Graph tools work once verification succeeds.',
                               'For mailbox tools assign an Exchange role to the enterprise application in this customer tenant (see README).']}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def add_tenant(alias: str, domain: str | None = None, tenant_id: str | None = None) -> dict:
        """Register a new customer tenant (status pending). Give a verified customer domain (tenant ID is looked up) or the tenant ID. Returns the admin consent link. Nothing changes in the customer tenant. Writes stay disabled."""
        client = actor.get()
        registry.require_manager(client)
        if not ALIAS.fullmatch(alias or ''):
            raise ValueError('Alias: lowercase letters, digits and hyphens, max 63 characters')
        if alias in registry.tenants:
            raise ValueError('Alias already exists')
        if bool(domain) == bool(tenant_id):
            raise ValueError('Provide either domain or tenant_id')
        resolved = str(uuid.UUID(tenant_id)) if tenant_id else await graph.resolve_tenant(domain)
        existing = registry.find_tenant_id(resolved)
        if existing:
            raise ValueError(f'Tenant already registered as {existing.alias}')
        tenant = Tenant(alias, resolved, '', False, 'pending', True)
        store.add_tenant(tenant, client['name'])
        registry.register(tenant, client)
        store.audit(client['name'], alias, 'add_tenant', resolved, 'succeeded')
        return {'alias': alias, 'tenant_id': resolved, 'status': 'pending', 'resolved_from': domain or 'tenant_id', **consent_steps(tenant)}

    @mcp.tool(annotations={'readOnlyHint': True, 'openWorldHint': False})
    def get_consent_link(tenant: str) -> dict:
        """Admin consent link for a tenant, e.g. to repeat consent after new permissions were added to the app."""
        return {'alias': tenant, **consent_steps(authorize(tenant, pending=True))}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def verify_tenant(tenant: str) -> dict:
        """Check that admin consent works by signing in as the app and reading the organization. Activates a pending tenant and stores its initial onmicrosoft.com domain."""
        client = actor.get()
        current = registry.managed(client, tenant)
        started = time.monotonic()
        try:
            organization = await graph.organization(current)
        except Exception:
            store.audit(client['name'], tenant, 'verify_tenant', current.tenant_id, 'failed', elapsed(started))
            return {'alias': tenant, 'verified': False, 'status': current.status,
                    'reason': 'App sign-in or Graph read failed. Consent missing, not yet propagated (wait a few minutes) or app certificate not uploaded.',
                    **consent_steps(current)}
        initial = next((d.get('name', '') for d in organization.get('verifiedDomains', []) if d.get('isInitial')), '')
        if organization.get('id') != current.tenant_id or not initial.endswith('.onmicrosoft.com'):
            store.audit(client['name'], tenant, 'verify_tenant', current.tenant_id, 'failed', elapsed(started))
            raise RuntimeError('Organization response does not match the registered tenant')
        store.update_tenant(tenant, organization=initial, status='active', display_name=organization.get('displayName'))
        registry.update(tenant, organization=initial, status='active')
        store.audit(client['name'], tenant, 'verify_tenant', current.tenant_id, 'succeeded', elapsed(started))
        try:
            roles = await graph.granted_roles(current)
        except Exception:
            roles = None
        return {'alias': tenant, 'verified': True, 'status': 'active', 'display_name': organization.get('displayName'),
                'granted_graph_permissions': roles,
                'organization': initial, 'exchange_notice': 'Mailbox tools additionally need an Exchange role for the enterprise application.'}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    def set_tenant_writes(tenant: str, enabled: bool, confirmed: bool = False) -> dict:
        """Enable or disable write tools for a tenant added via add_tenant. Requires confirmed=true after explicit operator confirmation."""
        client = actor.get()
        current = registry.managed(client, tenant)
        if enabled and not client.get('can_write', False):
            raise ValueError('This client has no write permission')
        if current.status != 'active':
            raise ValueError('Verify the tenant first')
        if confirmed is not True:
            return {'alias': tenant, 'writes_enabled': current.writes, 'requested': enabled, 'notice': 'Not changed. Repeat with confirmed=true after operator confirmation.'}
        store.update_tenant(tenant, writes=bool(enabled))
        registry.update(tenant, writes=bool(enabled))
        store.audit(client['name'], tenant, 'set_tenant_writes', 'enabled' if enabled else 'disabled', 'succeeded')
        return {'alias': tenant, 'writes_enabled': bool(enabled)}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'openWorldHint': False})
    def remove_tenant(tenant: str, confirmed: bool = False) -> dict:
        """Remove a tenant added via add_tenant from this MCP. Does not touch the customer tenant: delete the enterprise application there to revoke access. Requires confirmed=true."""
        client = actor.get()
        current = registry.managed(client, tenant)
        if confirmed is not True:
            return {'alias': tenant, 'tenant_id': current.tenant_id, 'notice': 'Not removed. Repeat with confirmed=true after operator confirmation.'}
        store.remove_tenant(tenant)
        registry.unregister(tenant)
        store.audit(client['name'], tenant, 'remove_tenant', current.tenant_id, 'succeeded')
        return {'alias': tenant, 'removed': True,
                'notice': 'Access still exists in Microsoft until the enterprise application is deleted in the customer tenant.'}

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_users(tenant: str, limit: int = 100) -> dict:
        """Read the first 1–999 users. Reports whether additional pages exist."""
        return await read(tenant, 'list_users', lambda t: graph.listing(t, 'users', 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses', limit))

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_groups(tenant: str, limit: int = 100) -> dict:
        """Read the first 1–999 groups."""
        return await read(tenant, 'list_groups', lambda t: graph.listing(t, 'groups', 'id,displayName,mail,groupTypes', limit))

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_licenses(tenant: str) -> dict:
        """Read subscribed license SKUs and consumption."""
        return await read(tenant, 'list_licenses', lambda t: graph.request(t, 'subscribedSkus'))

    @mcp.tool(annotations={'readOnlyHint': True})
    async def get_user(tenant: str, user_id: str) -> dict:
        """Read one user, assigned licenses and usage location by Entra object UUID."""
        user_id = str(uuid.UUID(user_id))
        return await read(tenant, 'get_user', lambda t: graph.request(t, f'users/{user_id}',
            {'$select': 'id,displayName,userPrincipalName,accountEnabled,usageLocation,assignedLicenses'}), user_id)

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_group_members(tenant: str, group_id: str, limit: int = 100) -> dict:
        """Read a bounded first page of group members by group UUID."""
        group_id = str(uuid.UUID(group_id))
        return await read(tenant, 'list_group_members', lambda t: graph.listing(t,
            f'groups/{group_id}/members', 'id,displayName', limit), group_id)

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_user_teams(tenant: str, user_id: str) -> dict:
        """Read Teams joined by a user; requires Team.ReadBasic.All. Does not read telephony settings."""
        user_id = str(uuid.UUID(user_id))
        return await read(tenant, 'list_user_teams', lambda t: graph.request(t,
            f'users/{user_id}/joinedTeams', {'$select': 'id,displayName,description'}), user_id)

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_license_change(tenant: str, user_id: str, add_sku_ids: list[str], remove_sku_ids: list[str]) -> dict:
        """Prepare direct license assignment/removal. Review exact SKU IDs and effects before confirming. Added SKUs enable all service plans. Group-based licensing is not removed by this tool. Usage location, capacity and mailbox retention requirements must be checked."""
        authorize(tenant, write=True)
        user_id = str(uuid.UUID(user_id))
        adds = [str(uuid.UUID(value)) for value in add_sku_ids]
        removes = [str(uuid.UUID(value)) for value in remove_sku_ids]
        if not (adds or removes) or len(adds) != len(set(adds)) or len(removes) != len(set(removes)) or set(adds) & set(removes):
            raise ValueError('Provide unique, disjoint add/remove SKU IDs')
        user = await read(tenant, 'resolve_license_target', lambda t: graph.request(t, f'users/{user_id}',
            {'$select': 'id,displayName,userPrincipalName,usageLocation,assignedLicenses'}), user_id)
        inventory = await read(tenant, 'resolve_license_inventory', lambda t: graph.request(t, 'subscribedSkus'))
        sku_names = {item['skuId']: item['skuPartNumber'] for item in inventory.get('value', [])}
        if not set(adds + removes) <= sku_names.keys():
            raise ValueError('SKU not present in customer inventory')
        if adds and not user.get('usageLocation'):
            raise ValueError('Set the user usageLocation before assigning licenses')
        payload = {'addLicenses': [{'skuId': value, 'disabledPlans': []} for value in adds], 'removeLicenses': removes}
        plan = store.plan(actor.get()['name'], tenant, 'assign_licenses', user_id, payload)
        plan.update({'resolved_user': user, 'add_skus': {s: sku_names[s] for s in adds},
                     'remove_skus': {s: sku_names[s] for s in removes},
                     'warning': 'License removal may affect mailbox/data access. No retention or mailbox conversion is performed.'})
        store.audit(actor.get()['name'], tenant, 'assign_licenses', user_id, 'planned')
        return plan

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_group_membership(tenant: str, group_id: str, user_id: str, add: bool) -> dict:
        """Prepare adding/removing a user in a static cloud-managed security or Microsoft 365 group. Group licensing may change. Membership of a Microsoft 365 group can affect Teams access; this does not manage Teams channels or telephony."""
        authorize(tenant, write=True)
        group_id, user_id = str(uuid.UUID(group_id)), str(uuid.UUID(user_id))
        group = await read(tenant, 'resolve_group', lambda t: graph.request(t, f'groups/{group_id}',
            {'$select': 'id,displayName,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,isAssignableToRole'}), group_id)
        if 'DynamicMembership' in group.get('groupTypes', []) or group.get('onPremisesSyncEnabled') or group.get('isAssignableToRole'):
            raise ValueError('Dynamic, synchronized and role-assignable groups are not supported')
        if group.get('mailEnabled') and 'Unified' not in group.get('groupTypes', []):
            raise ValueError('Distribution and mail-enabled security groups require Exchange management')
        if 'Unified' not in group.get('groupTypes', []) and not group.get('securityEnabled'):
            raise ValueError('Only security and Microsoft 365 groups are supported')
        user = await read(tenant, 'resolve_group_member', lambda t: graph.request(t, f'users/{user_id}',
            {'$select': 'id,displayName,userPrincipalName'}), user_id)
        action = 'add_group_member' if add else 'remove_group_member'
        plan = store.plan(actor.get()['name'], tenant, action, group_id, {'member_id': user_id})
        plan.update({'resolved_group': group, 'resolved_user': user})
        store.audit(actor.get()['name'], tenant, action, group_id, 'planned')
        return plan

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_distribution_membership(tenant: str, group_id: str, user_id: str, add: bool) -> dict:
        """Prepare adding/removing a user in a cloud distribution list (mail-enabled, non-Microsoft-365 group) via Exchange. Members receive the list's mail in their own mailbox. Confirm with execute_plan."""
        authorize(tenant, write=True)
        if type(add) is not bool:
            raise ValueError('add must be a boolean')
        group_id, user_id = str(uuid.UUID(group_id)), str(uuid.UUID(user_id))
        group = await read(tenant, 'resolve_distribution_list', lambda t: graph.request(t, f'groups/{group_id}',
            {'$select': 'id,displayName,mail,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled'}), group_id)
        if not group.get('mailEnabled') or 'Unified' in group.get('groupTypes', []) or group.get('onPremisesSyncEnabled'):
            raise ValueError('Only cloud distribution lists are supported; use prepare_group_membership for Microsoft 365 and security groups')
        user = await read(tenant, 'resolve_distribution_member', lambda t: graph.request(t, f'users/{user_id}',
            {'$select': 'id,displayName,userPrincipalName'}), user_id)
        address, upn = str(group.get('mail') or ''), str(user.get('userPrincipalName') or '')
        if not address or not upn:
            raise ValueError('Group address or user could not be resolved')
        plan = store.plan(actor.get()['name'], tenant, 'distribution_member', address, {'member': upn, 'member_id': user_id, 'add': add})
        plan.update({'resolved_group': group, 'resolved_user': user, 'add': add})
        store.audit(actor.get()['name'], tenant, 'distribution_member', address, 'planned')
        return plan

    @mcp.tool(annotations={'readOnlyHint': True})
    async def find_user_files(tenant: str, user_id: str, query: str) -> dict:
        """Find files and folders in a user's OneDrive whose name contains query (case-insensitive), e.g. a Teams recording. Walks the folder tree (max. depth 8, max. 5000 entries) because Graph's drive search does not support app-only access. query: 2-64 letters, digits, spaces, dots, hyphens."""
        user_id = str(uuid.UUID(user_id))
        if not FILE_QUERY.fullmatch(query or ''):
            raise ValueError('query: 2-64 letters, digits, spaces, dots, hyphens or underscores')
        needle = query.lower()

        async def walk(t):
            hits, scanned, pending = [], 0, [('', f'users/{user_id}/drive/root/children', 0)]
            truncated = False
            while pending:
                path, url, depth = pending.pop(0)
                data = await graph.request(t, url, {'$select': 'id,name,size,createdDateTime,lastModifiedDateTime,file,folder', '$top': '999'})
                truncated = truncated or '@odata.nextLink' in data
                for item in data.get('value', []):
                    scanned += 1
                    name = item.get('name', '')
                    full = f'{path}/{name}'
                    if needle in name.lower():
                        hits.append({'id': item.get('id'), 'name': name, 'path': full, 'size': item.get('size'),
                                     'created': item.get('createdDateTime'), 'modified': item.get('lastModifiedDateTime'),
                                     'is_folder': 'folder' in item})
                    if 'folder' in item and depth < 8 and ITEM_ID.fullmatch(item.get('id', '')):
                        pending.append((full, f"users/{user_id}/drive/items/{item['id']}/children", depth + 1))
                    if scanned >= 5000:
                        return hits, scanned, True
            return hits, scanned, truncated

        hits, scanned, truncated = await read(tenant, 'find_user_files', walk, user_id)
        return {'items': hits[:200], 'scanned': scanned, 'incomplete': truncated or len(hits) > 200}

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_user_folder(tenant: str, user_id: str, folder: str = '') -> dict:
        """List up to 200 entries of a folder in a user's OneDrive. folder: path below the drive root such as Recordings or Documents/Projekte; empty = root. Teams recordings are usually in Recordings (German: Aufzeichnungen)."""
        user_id = str(uuid.UUID(user_id))
        folder = (folder or '').strip('/')
        if folder and not DRIVE_PATH.fullmatch(folder):
            raise ValueError('folder: letters, digits, spaces, dots, hyphens, underscores and / only')
        path = f'users/{user_id}/drive/root/children' if not folder else f'users/{user_id}/drive/root:/{folder}:/children'
        data = await read(tenant, 'list_user_folder', lambda t: graph.request(t, path,
            {'$select': 'id,name,size,createdDateTime,lastModifiedDateTime,file,folder', '$top': '200'}), user_id)
        items = [{'id': i.get('id'), 'name': i.get('name'), 'size': i.get('size'), 'created': i.get('createdDateTime'),
                  'modified': i.get('lastModifiedDateTime'), 'is_folder': 'folder' in i} for i in data.get('value', [])]
        return {'folder': '/' + folder, 'items': items, 'more_available': '@odata.nextLink' in data}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_file_share(tenant: str, owner_user_id: str, item_id: str, recipient_user_id: str, role: str = 'read') -> dict:
        """Prepare sharing one file/folder from a user's OneDrive with another user of the same tenant (role read or write; write also allows download for Teams recordings). No invitation e-mail is sent; the recipient finds it under 'Shared with me'. Confirm with execute_plan."""
        authorize(tenant, write=True)
        if role not in ('read', 'write'):
            raise ValueError('role must be read or write')
        owner, recipient = str(uuid.UUID(owner_user_id)), str(uuid.UUID(recipient_user_id))
        if not ITEM_ID.fullmatch(item_id or ''):
            raise ValueError('Invalid drive item id (use an id from find_user_files)')
        item = await read(tenant, 'resolve_file', lambda t: graph.request(t, f'users/{owner}/drive/items/{item_id}',
            {'$select': 'id,name,size,parentReference,file,folder'}), item_id)
        user = await read(tenant, 'resolve_share_recipient', lambda t: graph.request(t, f'users/{recipient}',
            {'$select': 'id,displayName,userPrincipalName,mail'}), recipient)
        address = str(user.get('mail') or user.get('userPrincipalName') or '')
        if not address:
            raise ValueError('Recipient has no address')
        payload = {'owner': owner, 'item_id': item_id, 'recipient': address, 'role': role}
        plan = store.plan(actor.get()['name'], tenant, 'share_file', item_id, payload)
        plan.update({'resolved_item': {'name': item.get('name'), 'size': item.get('size'),
                                       'folder_path': (item.get('parentReference') or {}).get('path')},
                     'resolved_recipient': user, 'role': role})
        store.audit(actor.get()['name'], tenant, 'share_file', item_id, 'planned')
        return plan

    @mcp.tool(annotations={'readOnlyHint': True})
    async def list_mailboxes(tenant: str) -> dict:
        """Read at most 100 Exchange mailboxes. This is a bounded inventory, not a full export."""
        items = await read(tenant, 'list_mailboxes', lambda t: exchange.run(t, 'list_mailboxes'))
        return {'items': items, 'limit': 100, 'may_be_truncated': len(items) >= 100}

    @mcp.tool(annotations={'readOnlyHint': True})
    async def get_mailbox(tenant: str, user_id: str) -> dict:
        """Read one Exchange mailbox by its Entra object UUID or SMTP address (also shared and room mailboxes)."""
        reference = next(iter(mailbox_reference(user_id).values()))
        return await read(tenant, 'get_mailbox', lambda t: exchange.run(t, 'get_mailbox', reference), reference)

    @mcp.tool(annotations={'readOnlyHint': True})
    async def get_mailbox_permissions(tenant: str, mailbox: str, calendar_folder: str | None = None) -> dict:
        """Read who has full access, send-as and calendar permissions on a mailbox (Entra object UUID or SMTP address). calendar_folder: optional folder path from find_calendar_folders (e.g. /Kalender/Jahreskalender); default is the main calendar. Inherited and system entries are omitted."""
        reference = next(iter(mailbox_reference(mailbox).values()))
        extra = {'folder': validate_folder(calendar_folder)} if calendar_folder else None
        return await read(tenant, 'get_mailbox_permissions', lambda t: exchange.run(t, 'mailbox_permissions', reference, extra), reference)

    @mcp.tool(annotations={'readOnlyHint': True})
    async def find_calendar_folders(tenant: str, query: str) -> dict:
        """Search all user, shared, room and equipment mailboxes for calendar folders whose name contains query (3-64 characters). Slow on large tenants (one Exchange call per mailbox)."""
        items = await read(tenant, 'find_calendar_folders', lambda t: exchange.run(t, 'find_calendar_folders', '', {'query': query}), query)
        return {'items': items or [], 'query': query}

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_mailbox_permission(tenant: str, mailbox: str, user_id: str, right: str, add: bool = True,
                                         calendar_role: str | None = None, automapping: bool = True,
                                         calendar_folder: str | None = None) -> dict:
        """Prepare granting or removing a mailbox permission for a user. right: full_access (open the mailbox; automapping adds it to Outlook), send_as, or calendar (main calendar or calendar_folder from find_calendar_folders; calendar_role Reviewer = read, Author = create own, Editor = edit all). mailbox: Entra object UUID or SMTP address; user_id: Entra user UUID. Confirm with execute_plan."""
        authorize(tenant, write=True)
        if right not in MAILBOX_RIGHTS:
            raise ValueError('right must be full_access, send_as or calendar')
        if type(add) is not bool or type(automapping) is not bool:
            raise ValueError('add and automapping must be booleans')
        if right == 'calendar' and add and calendar_role not in CALENDAR_ROLES:
            raise ValueError('calendar_role must be Reviewer, Author or Editor')
        reference = next(iter(mailbox_reference(mailbox).values()))
        user_id = str(uuid.UUID(user_id))
        user = await read(tenant, 'resolve_permission_user', lambda t: graph.request(t, f'users/{user_id}',
            {'$select': 'id,displayName,userPrincipalName,accountEnabled'}), user_id)
        target = await read(tenant, 'resolve_permission_mailbox', lambda t: exchange.run(t, 'get_mailbox', reference), reference)
        address = str((target or {}).get('PrimarySmtpAddress') or '')
        upn = str(user.get('userPrincipalName') or '')
        if not address or not upn:
            raise ValueError('Mailbox or user could not be resolved')
        if target.get('ExternalDirectoryObjectId') == user_id:
            raise ValueError('User already owns this mailbox')
        payload = {'right': right, 'trustee': upn, 'trustee_id': user_id, 'add': add,
                   'automapping': automapping if right == 'full_access' else False}
        if right == 'calendar' and add:
            payload['role'] = calendar_role
        if calendar_folder:
            if right != 'calendar':
                raise ValueError('calendar_folder applies to right=calendar only')
            payload['folder'] = validate_folder(calendar_folder)
        action = 'mailbox_permission'
        plan = store.plan(actor.get()['name'], tenant, action, address, payload)
        plan.update({'resolved_mailbox': target, 'resolved_user': user,
                     'change': {'right': right, 'add': add, 'calendar_role': payload.get('role'), 'calendar_folder': payload.get('folder'),
                                'automapping': payload['automapping']}})
        if right == 'full_access' and add:
            plan['notice'] += ' Full access lets the user read all mail in this mailbox; it does not allow sending as the mailbox.'
        store.audit(actor.get()['name'], tenant, action, address, 'planned')
        return plan

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': False})
    async def prepare_change(tenant: str, action: str, user_id: str) -> dict:
        """Prepare, but do not execute, block_signin, revoke_sessions or convert_shared. Show the plan to the operator and obtain explicit confirmation before execute_plan. Session revocation is not immediate for every token. This is not complete offboarding."""
        authorize(tenant, write=True)
        if action not in ('block_signin', 'revoke_sessions', 'convert_shared'):
            raise ValueError('Supported actions: block_signin, revoke_sessions, convert_shared')
        user_id = str(uuid.UUID(user_id))
        target = await read(tenant, 'resolve_change_target', lambda t: graph.request(t, f'users/{user_id}', {'$select': 'id,displayName,userPrincipalName'}), user_id)
        if action == 'convert_shared':
            await read(tenant, 'resolve_mailbox', lambda t: exchange.run(t, 'get_mailbox', user_id), user_id)
        result = store.plan(actor.get()['name'], tenant, action, user_id)
        result['resolved_user'] = target
        if action == 'convert_shared':
            result['prerequisites'] = 'Check hybrid source of authority, mailbox size, archive, holds, retention and licensing. This tool does not remove licenses.'
        store.audit(actor.get()['name'], tenant, action, user_id, 'planned')
        return result

    @mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False})
    async def execute_plan(tenant: str, plan_id: str, confirmed: bool = False) -> dict:
        """Execute a reviewed plan once, only after explicit operator confirmation. confirmed must be true. On timeout/failure read remote state before preparing another plan."""
        customer = authorize(tenant, write=True)
        if confirmed is not True:
            raise ValueError('Explicit confirmation required')
        name = actor.get()['name']
        action, target = store.claim(plan_id, name, tenant)
        store.audit(name, tenant, action, target, 'executing')
        started = time.monotonic()
        try:
            if action == 'block_signin':
                result = await graph.block(customer, target)
            elif action == 'convert_shared':
                result = await exchange.run(customer, action, target)
            elif action == 'share_file':
                result = await graph.share_file(customer, store.payload(plan_id))
            elif action == 'distribution_member':
                result = await exchange.run(customer, 'set_distribution_member', target, store.payload(plan_id))
            elif action == 'mailbox_permission':
                result = await exchange.run(customer, 'set_mailbox_permission', target, store.payload(plan_id))
            elif action in ('assign_licenses', 'revoke_sessions', 'add_group_member', 'remove_group_member'):
                result = await graph.admin_change(customer, action, target, store.payload(plan_id))
            else:
                raise ValueError('Unsupported stored action')
        except BaseException:
            store.finish(plan_id, 'unknown')
            store.audit(name, tenant, action, target, 'unknown_verify_remote_state', elapsed(started))
            raise RuntimeError('Execution did not complete cleanly. Plan is consumed. Check remote state before retrying.') from None
        store.finish(plan_id, 'succeeded')
        store.audit(name, tenant, action, target, 'succeeded', elapsed(started))
        return {'tenant': tenant, 'action': action, 'target': target, 'result': result}

    async def health(_):
        return JSONResponse({'status': 'ok'})

    transport = mcp.streamable_http_app()
    async def consent_done(_):
        return HTMLResponse(CONSENT_PAGE, headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                                                   'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'"})

    app = Starlette(routes=[Route('/healthz', health), Route('/consent-done', consent_done), Mount('/', app=transport)], lifespan=transport.router.lifespan_context)
    return Authentication(app, registry)


def main():
    uvicorn.run(create_app(), host='0.0.0.0', port=8000, access_log=False, proxy_headers=False)


if __name__ == '__main__':
    main()
