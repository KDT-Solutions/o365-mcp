import asyncio
import json

import httpx
import pytest

from m365_mcp.server import create_app


class FakeGraph:
    def __init__(self):
        self.calls = []

    async def request(self, tenant, path, params=None, body=None):
        self.calls.append((tenant.alias, path))
        if path == 'subscribedSkus':
            return {'value': [{'skuId': '00000000-0000-0000-0000-000000000006', 'skuPartNumber': 'TEST_SKU'}]}
        if path.startswith('groups/'):
            return {'id': path.split('/')[1], 'displayName': 'Test Group', 'securityEnabled': True, 'groupTypes': []}
        return {'id': '00000000-0000-0000-0000-000000000005', 'displayName': 'Test User', 'usageLocation': 'DE'}

    async def admin_change(self, tenant, action, target, payload):
        self.calls.append((action, tenant.alias, target, payload))
        return {'success': True}

    async def block(self, tenant, target):
        self.calls.append(('block', tenant.alias, target))
        return {'success': True}

    async def listing(self, *args):
        return {'items': []}

    consented = False

    async def resolve_tenant(self, domain):
        self.calls.append(('resolve', domain))
        return '00000000-0000-0000-0000-0000000000aa'

    async def granted_roles(self, tenant):
        return ['User.Read.All']

    async def organization(self, tenant):
        self.calls.append(('organization', tenant.alias))
        if not self.consented:
            raise RuntimeError('AADSTS consent missing')
        return {'id': tenant.tenant_id, 'displayName': 'Kunde Gamma AG',
                'verifiedDomains': [{'name': 'gamma.example', 'isInitial': False}, {'name': 'gammaag.onmicrosoft.com', 'isInitial': True}]}


class FakeExchange:
    def __init__(self):
        self.calls = []

    async def run(self, tenant, action, target='', extra=None):
        self.calls.append((action, target, extra))
        if action == 'get_mailbox':
            return {'DisplayName': 'Jugendfeuerwehr', 'PrimarySmtpAddress': 'jugend@alpha.example',
                    'RecipientTypeDetails': 'SharedMailbox', 'ExternalDirectoryObjectId': '00000000-0000-0000-0000-000000000009'}
        if action == 'mailbox_permissions':
            return {'mailbox': 'jugend@alpha.example', 'full_access': [], 'send_as': [], 'calendar': []}
        return []


def test_http_mcp_auth_acl_and_confirmation(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    provider = FakeGraph()
    app = create_app(config, tmp_path / 'state.db', provider, FakeExchange())

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                assert (await client.get('/healthz')).status_code == 200
                assert (await client.post('/mcp')).status_code == 401
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}
                async def rpc(method, params):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
                    assert response.status_code == 200, response.text
                    return response.json()
                initialized = await rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}})
                assert 'serverInfo' in initialized['result']
                async def tool(name, args):
                    return (await rpc('tools/call', {'name': name, 'arguments': args}))['result']
                listed = await tool('list_tenants', {})
                assert 'alpha' in json.dumps(listed)
                assert 'beta' not in json.dumps(listed)
                denied = await tool('list_users', {'tenant': 'beta'})
                assert denied.get('isError') is True
                assert provider.calls == []
                plan = await tool('prepare_change', {'tenant': 'alpha', 'action': 'block_signin', 'user_id': '00000000-0000-0000-0000-000000000005'})
                assert not plan.get('isError'), plan
                content = json.loads(plan['content'][0]['text'])
                identifier = content['plan_id']
                args = {'tenant': 'alpha', 'plan_id': identifier}
                unconfirmed = await tool('execute_plan', args)
                assert unconfirmed.get('isError') is True
                args['confirmed'] = True
                result = await tool('execute_plan', args)
                assert not result.get('isError'), result
                again = await tool('execute_plan', args)
                assert again.get('isError') is True
                assert len([x for x in provider.calls if x[0] == 'block']) == 1
                license_plan = await tool('prepare_license_change', {'tenant': 'alpha',
                    'user_id': '00000000-0000-0000-0000-000000000005',
                    'add_sku_ids': ['00000000-0000-0000-0000-000000000006'], 'remove_sku_ids': []})
                assert not license_plan.get('isError'), license_plan
                assert not any(x[0] == 'assign_licenses' for x in provider.calls)
                license_id = json.loads(license_plan['content'][0]['text'])['plan_id']
                changed = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': license_id, 'confirmed': True})
                assert not changed.get('isError'), changed
                license_call = next(x for x in provider.calls if x[0] == 'assign_licenses')
                assert license_call[3] == {'addLicenses': [{'skuId': '00000000-0000-0000-0000-000000000006', 'disabledPlans': []}], 'removeLicenses': []}
                group_plan = await tool('prepare_group_membership', {'tenant': 'alpha',
                    'group_id': '00000000-0000-0000-0000-000000000007',
                    'user_id': '00000000-0000-0000-0000-000000000005', 'add': False})
                assert not group_plan.get('isError'), group_plan
                group_id = json.loads(group_plan['content'][0]['text'])['plan_id']
                changed = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': group_id, 'confirmed': True})
                assert not changed.get('isError'), changed
                assert any(x[0] == 'remove_group_member' for x in provider.calls)
                version = await tool('get_version', {})
                assert 'commit' in version['content'][0]['text']
                certificate = json.loads((await tool('get_app_certificate', {}))['content'][0]['text'])
                assert certificate['pem'].startswith('-----BEGIN CERTIFICATE-----')
                audit = await tool('get_audit_log', {})
                assert not audit.get('isError'), audit
                entries = audit['structuredContent']['result']
                assert entries and {entry['tenant'] for entry in entries} == {'alpha'}
                foreign = await tool('get_audit_log', {'tenant': 'beta'})
                assert foreign.get('isError') is True
                bad_host = await client.post('/mcp', headers={**headers, 'Host': 'attacker.example'}, json={})
                assert bad_host.status_code == 421
    asyncio.run(scenario())


def test_custom_mcp_path(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    monkeypatch.setenv('MCP_PATH', '/o365')
    app = create_app(config, tmp_path / 'state.db', FakeGraph(), FakeExchange())

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}
                body = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                        'params': {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}}
                response = await client.post('/o365', headers=headers, json=body)
                assert response.status_code == 200, response.text
                assert 'serverInfo' in response.json()['result']
                assert (await client.post('/mcp', headers=headers, json=body)).status_code == 404
    asyncio.run(scenario())


def test_tenant_management_persists_and_is_restricted(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    monkeypatch.setenv('CONSENT_REDIRECT_URI', 'https://mcp.example.com/consent-done')
    provider = FakeGraph()
    state = tmp_path / 'state.db'

    async def session(app, token, steps):
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json, text/event-stream'}
                async def tool(name, args):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                               'params': {'name': name, 'arguments': args}})
                    assert response.status_code == 200, response.text
                    result = response.json()['result']
                    return result, (None if result.get('isError') else json.loads(result['content'][0]['text']))
                return await steps(client, tool)

    async def as_alice(client, tool):
        page = await client.get('/consent-done?error=<script>x</script>&tenant=evil')
        assert page.status_code == 200 and '<script>' not in page.text and 'evil' not in page.text
        result, added = await tool('add_tenant', {'alias': 'gamma', 'domain': 'gamma.example'})
        assert added['status'] == 'pending' and added['tenant_id'] == '00000000-0000-0000-0000-0000000000aa'
        assert added['consent_url'].startswith('https://login.microsoftonline.com/00000000-0000-0000-0000-0000000000aa/adminconsent?')
        assert 'redirect_uri=https%3A%2F%2Fmcp.example.com%2Fconsent-done' in added['consent_url']
        assert (await tool('add_tenant', {'alias': 'gamma2', 'tenant_id': '00000000-0000-0000-0000-0000000000aa'}))[0]['isError']
        assert (await tool('add_tenant', {'alias': 'alpha', 'domain': 'other.example'}))[0]['isError']
        assert (await tool('add_tenant', {'alias': 'Bad Alias', 'domain': 'x.example'}))[0]['isError']
        assert (await tool('list_users', {'tenant': 'gamma'}))[0]['isError']
        assert (await tool('verify_tenant', {'tenant': 'alpha'}))[0]['isError']
        _, failed = await tool('verify_tenant', {'tenant': 'gamma'})
        assert failed['verified'] is False and 'consent_url' in failed
        provider.consented = True
        _, verified = await tool('verify_tenant', {'tenant': 'gamma'})
        assert verified['verified'] is True and verified['organization'] == 'gammaag.onmicrosoft.com'
        assert not (await tool('list_users', {'tenant': 'gamma'}))[0].get('isError')
        _, preview = await tool('set_tenant_writes', {'tenant': 'gamma', 'enabled': True})
        assert preview['writes_enabled'] is False
        _, enabled = await tool('set_tenant_writes', {'tenant': 'gamma', 'enabled': True, 'confirmed': True})
        assert enabled['writes_enabled'] is True

    async def after_restart(client, tool):
        result, _ = await tool('list_tenants', {})
        gamma = next(t for t in result['structuredContent']['result'] if t['alias'] == 'gamma')
        assert gamma['status'] == 'active' and gamma['writes_enabled'] is True and gamma['source'] == 'mcp'
        _, kept = await tool('remove_tenant', {'tenant': 'gamma'})
        assert 'removed' not in kept
        _, removed = await tool('remove_tenant', {'tenant': 'gamma', 'confirmed': True})
        assert removed['removed'] is True
        assert (await tool('list_users', {'tenant': 'gamma'}))[0]['isError']

    async def as_bob(client, tool):
        assert (await tool('add_tenant', {'alias': 'delta', 'domain': 'delta.example'}))[0]['isError']
        assert (await tool('verify_tenant', {'tenant': 'gamma'}))[0]['isError']
        assert (await tool('list_users', {'tenant': 'gamma'}))[0]['isError']

    asyncio.run(session(create_app(config, state, provider, FakeExchange()), 'test-token', as_alice))
    asyncio.run(session(create_app(config, state, provider, FakeExchange()), 'bob-token', as_bob))
    asyncio.run(session(create_app(config, state, provider, FakeExchange()), 'test-token', after_restart))


def test_mailbox_permission_plan(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    graph, exchange = FakeGraph(), FakeExchange()
    app = create_app(config, tmp_path / 'state.db', graph, exchange)

    async def original_request(tenant, path, params=None, body=None):
        return {'id': '00000000-0000-0000-0000-000000000005', 'displayName': 'Test User', 'userPrincipalName': 'test.user@alpha.example'}
    graph.request = original_request

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}
                async def tool(name, args):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                               'params': {'name': name, 'arguments': args}})
                    result = response.json()['result']
                    return result, (None if result.get('isError') else json.loads(result['content'][0]['text']))
                result, permissions = await tool('get_mailbox_permissions', {'tenant': 'alpha', 'mailbox': 'Jugend@alpha.example'})
                assert permissions['mailbox'] == 'jugend@alpha.example'
                assert exchange.calls[-1] == ('mailbox_permissions', 'jugend@alpha.example', None)
                for bad in ('x; Remove-Mailbox', "a'@b.ch", ''):
                    assert (await tool('get_mailbox_permissions', {'tenant': 'alpha', 'mailbox': bad}))[0]['isError']
                assert (await tool('get_mailbox_permissions', {'tenant': 'beta', 'mailbox': 'jugend@alpha.example'}))[0]['isError']
                args = {'tenant': 'alpha', 'mailbox': 'jugend@alpha.example', 'user_id': '00000000-0000-0000-0000-000000000005'}
                assert (await tool('prepare_mailbox_permission', {**args, 'right': 'owner'}))[0]['isError']
                assert (await tool('prepare_mailbox_permission', {**args, 'right': 'calendar'}))[0]['isError']
                calls_before = len(exchange.calls)
                _, plan = await tool('prepare_mailbox_permission', {**args, 'right': 'full_access'})
                assert plan['target'] == 'jugend@alpha.example' and plan['change']['automapping'] is True
                assert not any(c[0] == 'set_mailbox_permission' for c in exchange.calls[calls_before:])
                result, done = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
                assert not result.get('isError'), result
                action, target, extra = exchange.calls[-1]
                assert (action, target) == ('set_mailbox_permission', 'jugend@alpha.example')
                assert extra['right'] == 'full_access' and extra['trustee'] == 'test.user@alpha.example' and extra['add'] is True
                _, calendar = await tool('prepare_mailbox_permission', {**args, 'right': 'calendar', 'calendar_role': 'Editor'})
                assert calendar['change']['calendar_role'] == 'Editor'
    asyncio.run(scenario())


def test_distribution_membership_plan(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    graph, exchange = FakeGraph(), FakeExchange()
    app = create_app(config, tmp_path / 'state.db', graph, exchange)
    groups = {'00000000-0000-0000-0000-00000000000a': {'id': 'a', 'mail': 'liste@alpha.example', 'mailEnabled': True, 'groupTypes': []},
              '00000000-0000-0000-0000-00000000000b': {'id': 'b', 'mail': 'team@alpha.example', 'mailEnabled': True, 'groupTypes': ['Unified']}}

    async def request(tenant, path, params=None, body=None):
        if path.startswith('groups/'):
            return groups[path.split('/')[1]]
        return {'id': '00000000-0000-0000-0000-000000000005', 'displayName': 'Test User', 'userPrincipalName': 'test.user@alpha.example'}
    graph.request = request

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}
                async def tool(name, args):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                               'params': {'name': name, 'arguments': args}})
                    result = response.json()['result']
                    return result, (None if result.get('isError') else json.loads(result['content'][0]['text']))
                base = {'tenant': 'alpha', 'user_id': '00000000-0000-0000-0000-000000000005', 'add': False}
                assert (await tool('prepare_distribution_membership', {**base, 'group_id': '00000000-0000-0000-0000-00000000000b'}))[0]['isError']
                _, plan = await tool('prepare_distribution_membership', {**base, 'group_id': '00000000-0000-0000-0000-00000000000a'})
                assert plan['target'] == 'liste@alpha.example'
                assert not exchange.calls
                result, _ = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
                assert not result.get('isError'), result
                assert exchange.calls[-1] == ('set_distribution_member', 'liste@alpha.example',
                                              {'member': 'test.user@alpha.example', 'member_id': '00000000-0000-0000-0000-000000000005', 'add': False})
    asyncio.run(scenario())


def test_file_share_plan(config, tmp_path, monkeypatch):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    graph, exchange = FakeGraph(), FakeExchange()
    app = create_app(config, tmp_path / 'state.db', graph, exchange)
    paths, shares = [], []

    async def request(tenant, path, params=None, body=None):
        paths.append(path)
        if path.endswith('/drive/root/children'):
            return {'value': [{'id': '01FOLDER', 'name': 'Recordings', 'folder': {}}, {'id': '01OTHER', 'name': 'Notes.docx', 'file': {}}]}
        if path.endswith('/drive/items/01FOLDER/children'):
            return {'value': [{'id': '01ABC!12', 'name': 'Xylem Meeting.mp4', 'size': 5, 'file': {}}]}
        if '/drive/items/' in path:
            return {'id': '01ABC!12', 'name': 'Meeting.mp4', 'size': 5, 'parentReference': {'path': '/drive/root:/Recordings'}}
        return {'id': '00000000-0000-0000-0000-000000000005', 'displayName': 'Test User', 'userPrincipalName': 'test.user@alpha.example'}
    async def share_file(tenant, payload):
        shares.append(payload)
        return {'shared_with': payload['recipient']}
    graph.request, graph.share_file = request, share_file

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}
                async def tool(name, args):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                               'params': {'name': name, 'arguments': args}})
                    result = response.json()['result']
                    return result, (None if result.get('isError') else json.loads(result['content'][0]['text']))
                user = '00000000-0000-0000-0000-000000000005'
                assert (await tool('find_user_files', {'tenant': 'alpha', 'user_id': user, 'query': "x') or ('"}))[0]['isError']
                _, found = await tool('find_user_files', {'tenant': 'alpha', 'user_id': user, 'query': 'Xylem'})
                assert [i['path'] for i in found['items']] == ['/Recordings/Xylem Meeting.mp4'] and found['scanned'] == 3
                assert found['method'] == 'folder_walk'
                async def inventory(t, uid):
                    return [{'id': '01ABC!12', 'name': 'Xylem Meeting.mp4', 'parentReference': {'path': '/drive/root:/Recordings'}, 'file': {}},
                            {'id': '01OTHER', 'name': 'Notes.docx', 'parentReference': {'path': '/drive/root:'}, 'file': {}}], True
                graph.drive_inventory = inventory
                _, found = await tool('find_user_files', {'tenant': 'alpha', 'user_id': user, 'query': 'xylem'})
                assert found['method'] == 'delta' and [i['path'] for i in found['items']] == ['/Recordings/Xylem Meeting.mp4']
                assert (await tool('prepare_file_share', {'tenant': 'alpha', 'owner_user_id': user, 'item_id': '../x', 'recipient_user_id': user}))[0]['isError']
                _, plan = await tool('prepare_file_share', {'tenant': 'alpha', 'owner_user_id': user, 'item_id': '01ABC!12',
                                                            'recipient_user_id': user, 'role': 'write'})
                assert plan['resolved_item']['name'] == 'Meeting.mp4' and not shares
                result, _ = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
                assert not result.get('isError'), result
                assert shares == [{'owner': user, 'item_id': '01ABC!12', 'recipient': 'test.user@alpha.example', 'role': 'write'}]
    asyncio.run(scenario())
