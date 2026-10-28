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


class FakeExchange:
    async def run(self, *args):
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
