import asyncio

import pytest

from m365_mcp import security

USER = '00000000-0000-0000-0000-000000000005'


class FakeGraph:
    def __init__(self, items=None):
        self.calls = []
        self.items = items or []

    async def collect(self, tenant, path, params, limit, api='v1.0'):
        self.calls.append((path, params, api))
        return self.items[:limit], False

    async def request(self, tenant, path, params=None, body=None, method=None, api='v1.0'):
        self.calls.append((path, body, method))
        if method == 'POST':
            return {'success': True}
        if path.endswith('/history'):
            return {'value': []}
        if path.startswith('identityProtection/riskyUsers/'):
            raise RuntimeError('Graph HTTP 404; request-id=x')
        if path.endswith('messageRules'):
            return {'value': [{'displayName': 'fw', 'isEnabled': True, 'actions': {'forwardTo': [{'emailAddress': {'address': 'x@evil.example'}}]}},
                              {'displayName': 'ok', 'isEnabled': True, 'actions': {'moveToFolder': 'abc'}}]}
        return {'success': True}


def sign_in(ip, country, code=0):
    return {'createdDateTime': '2026-10-30T13:14:30Z', 'appDisplayName': 'SharePoint', 'ipAddress': ip,
            'location': {'city': 'Kassel', 'countryOrRegion': country}, 'status': {'errorCode': code, 'failureReason': 'blocked'},
            'riskLevelDuringSignIn': 'none'}


def test_sign_ins_filter_and_summary():
    graph = FakeGraph([sign_in('1.1.1.1', 'DE'), sign_in('1.1.1.1', 'DE', 53011), sign_in('2.2.2.2', 'CH')])
    result = asyncio.run(security.sign_ins(graph, None, USER, 24, True, False, 100))
    path, params, api = graph.calls[0]
    assert path == 'auditLogs/signIns' and api == 'v1.0' and f"userId eq '{USER}'" in params['$filter']
    assert result['summary']['countries'] == {'DE': 2, 'CH': 1}
    assert result['summary']['failures'] == {'53011 blocked': 1}
    assert result['items'][0]['failure_reason'] is None


def test_non_interactive_uses_beta():
    graph = FakeGraph()
    asyncio.run(security.sign_ins(graph, None, USER, 24, False, True, 10))
    _, params, api = graph.calls[0]
    assert api == 'beta' and 'nonInteractiveUser' in params['$filter'] and 'errorCode ne 0' in params['$filter']


def test_invalid_input_rejected():
    with pytest.raises(ValueError):
        asyncio.run(security.sign_ins(FakeGraph(), None, "x' or 1 eq 1", 24, True, False, 10))
    with pytest.raises(ValueError):
        asyncio.run(security.sign_ins(FakeGraph(), None, USER, 9999, True, False, 10))
    with pytest.raises(ValueError):
        asyncio.run(security.risk_action(FakeGraph(), None, 'delete_user', USER))


def test_risky_user_not_listed_and_inbox_rules():
    graph = FakeGraph()
    risk = asyncio.run(security.risky_user(graph, None, USER))
    assert risk['listed'] is False
    rules = asyncio.run(security.inbox_rules(graph, None, USER))
    assert rules['forwarding_or_deleting_rules'] == ['fw']


def test_risk_action_posts_user_id():
    graph = FakeGraph()
    asyncio.run(security.risk_action(graph, None, 'dismiss_risk', USER))
    assert graph.calls[-1] == ('identityProtection/riskyUsers/dismiss', {'userIds': [USER]}, 'POST')
