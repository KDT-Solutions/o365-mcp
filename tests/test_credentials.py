import asyncio
import json
import sqlite3

import httpx
import pytest

from m365_mcp.providers import PASSWORD_GROUPS, Graph, generate_password
from m365_mcp.server import create_app
from test_http import FakeExchange

USER = '00000000-0000-0000-0000-000000000005'
METHODS = [
    {'@odata.type': '#microsoft.graph.passwordAuthenticationMethod', 'id': '28c10230-6103-485e-b985-444c60001490'},
    {'@odata.type': '#microsoft.graph.phoneAuthenticationMethod', 'id': '3179e48a-750b-4051-897c-87b9720928f7', 'phoneType': 'mobile', 'phoneNumber': '+41 79 000 00 00'},
    {'@odata.type': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod', 'id': 'abc-def_1', 'displayName': 'Old Phone'},
]


class FakeGraph(Graph):
    """Real Graph logic with the HTTP layer replaced."""

    def __init__(self, user=None, fail_delete=False):
        self.calls, self.methods = [], list(METHODS)
        self.user = user or {'id': USER, 'displayName': 'Test User', 'userPrincipalName': 'test.user@alpha.example'}
        self.fail_delete = fail_delete

    async def request(self, tenant, path, params=None, body=None, method=None):
        self.calls.append((method or ('PATCH' if body is not None else 'GET'), path, body))
        if path.endswith('/authentication/methods'):
            return {'value': self.methods}
        if method == 'DELETE':
            if self.fail_delete and 'phoneMethods' in path:
                raise RuntimeError('Graph HTTP 400; request-id=x')
            self.methods = [m for m in self.methods if m['id'] != path.rsplit('/', 1)[1]]
            return {'success': True}
        return self.user if body is None else {'success': True}


def test_generated_password_is_complex_and_unambiguous():
    passwords = {generate_password() for _ in range(200)}
    assert len(passwords) == 200
    for password in passwords:
        assert len(password) == 16
        assert all(any(c in group for c in password) for group in PASSWORD_GROUPS)
        assert not set(password) & set('0O1lI')


def run_tools(config, tmp_path, monkeypatch, graph, steps):
    monkeypatch.setenv('ALLOWED_HOSTS', 'testserver')
    app = create_app(config, tmp_path / 'state.db', graph, FakeExchange())

    async def scenario():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                headers = {'Authorization': 'Bearer test-token', 'Accept': 'application/json, text/event-stream'}

                async def tool(name, args):
                    response = await client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                               'params': {'name': name, 'arguments': args}})
                    result = response.json()['result']
                    return result, (None if result.get('isError') else json.loads(result['content'][0]['text']))
                await steps(tool)
    asyncio.run(scenario())


def test_password_reset_returns_password_once_and_never_stores_it(config, tmp_path, monkeypatch):
    graph = FakeGraph()

    async def steps(tool):
        _, plan = await tool('prepare_password_reset', {'tenant': 'alpha', 'user_id': USER})
        assert plan['force_change_next_sign_in'] is True and plan['revoke_sessions'] is True
        assert not any(c[0] == 'PATCH' for c in graph.calls)
        assert (await tool('prepare_password_reset', {'tenant': 'beta', 'user_id': USER}))[0]['isError']
        result, done = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
        assert not result.get('isError'), result
        password = done['result']['temporary_password']
        patch = next(c for c in graph.calls if c[0] == 'PATCH')
        assert patch[1] == f'users/{USER}'
        assert patch[2] == {'passwordProfile': {'forceChangePasswordNextSignIn': True, 'password': password}}
        assert ('POST', f'users/{USER}/revokeSignInSessions', {}) in graph.calls
        assert done['result']['sessions_revoked'] is True
        with sqlite3.connect(tmp_path / 'state.db') as db:
            dump = '\n'.join(db.iterdump())
        assert password not in dump
        assert (await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True}))[0]['isError']
    run_tools(config, tmp_path, monkeypatch, graph, steps)


@pytest.mark.parametrize('user', [{'id': USER, 'onPremisesSyncEnabled': True}, {'id': USER, 'userType': 'Guest'}])
def test_credential_reset_refuses_synced_and_guest_users(config, tmp_path, monkeypatch, user):
    graph = FakeGraph(user)

    async def steps(tool):
        for name in ('prepare_password_reset', 'prepare_mfa_reset'):
            assert (await tool(name, {'tenant': 'alpha', 'user_id': USER}))[0]['isError']
    run_tools(config, tmp_path, monkeypatch, graph, steps)


def test_mfa_reset_deletes_methods_phone_last_and_keeps_password(config, tmp_path, monkeypatch):
    graph = FakeGraph()

    async def steps(tool):
        _, listed = await tool('list_auth_methods', {'tenant': 'alpha', 'user_id': USER})
        assert '+41' not in json.dumps(listed)
        assert [m['removable'] for m in listed['methods']] == [False, True, True]
        _, plan = await tool('prepare_mfa_reset', {'tenant': 'alpha', 'user_id': USER, 'revoke_sessions': False})
        assert plan['methods_to_delete'] == ['phoneAuthenticationMethod', 'microsoftAuthenticatorAuthenticationMethod']
        assert not any(c[0] == 'DELETE' for c in graph.calls)
        result, done = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
        assert not result.get('isError'), result
        deletes = [c[1] for c in graph.calls if c[0] == 'DELETE']
        assert deletes == [f'users/{USER}/authentication/microsoftAuthenticatorMethods/abc-def_1',
                           f'users/{USER}/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7']
        assert done['result']['remaining_removable_methods'] == []
        assert 'sessions_revoked' not in done['result']
        assert not any('revokeSignInSessions' in c[1] for c in graph.calls)
        _, log = await tool('get_audit_log', {'tenant': 'alpha', 'action': 'reset_mfa'})
        assert log['outcome'] == 'succeeded'
    run_tools(config, tmp_path, monkeypatch, graph, steps)


def test_mfa_reset_reports_partial_failure(config, tmp_path, monkeypatch):
    graph = FakeGraph(fail_delete=True)

    async def steps(tool):
        _, plan = await tool('prepare_mfa_reset', {'tenant': 'alpha', 'user_id': USER})
        _, done = await tool('execute_plan', {'tenant': 'alpha', 'plan_id': plan['plan_id'], 'confirmed': True})
        assert done['result']['remaining_removable_methods'] == ['phoneAuthenticationMethod']
        assert [m['deleted'] for m in done['result']['methods']] == [True, False]
        _, log = await tool('get_audit_log', {'tenant': 'alpha', 'action': 'reset_mfa'})
        assert log['outcome'] == 'partial'
    run_tools(config, tmp_path, monkeypatch, graph, steps)
