import hashlib
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from m365_mcp.core import Registry, Store


@pytest.fixture
def config(tmp_path):
    data = {'client_id': '00000000-0000-0000-0000-000000000001',
            'tenants': [{'alias': alias, 'tenant_id': f'00000000-0000-0000-0000-00000000000{index}',
                         'organization': f'{alias}.onmicrosoft.com', 'writes': True}
                        for index, alias in enumerate(('alpha', 'beta'), 2)],
            'clients': [{'name': 'alice', 'token_sha256': hashlib.sha256(b'test-token').hexdigest(),
                         'tenants': ['alpha'], 'can_write': True}]}
    path = tmp_path / 'tenants.json'
    path.write_text(json.dumps(data))
    return path


def test_authentication_and_cross_tenant_denial(config):
    registry = Registry(config)
    assert registry.authenticate('wrong') is None
    alice = registry.authenticate('test-token')
    assert registry.authorize(alice, 'alpha').alias == 'alpha'
    with pytest.raises(ValueError, match='denied'):
        registry.authorize(alice, 'beta')
    alice['can_write'] = False
    with pytest.raises(ValueError, match='disabled'):
        registry.authorize(alice, 'alpha', True)


def test_plans_are_actor_and_tenant_bound_and_single_use(tmp_path):
    store = Store(tmp_path / 'state.db')
    plan = store.plan('alice', 'alpha', 'convert_shared', 'object-id')['plan_id']
    for actor, tenant in [('bob', 'alpha'), ('alice', 'beta')]:
        with pytest.raises(ValueError):
            store.claim(plan, actor, tenant)
    assert store.claim(plan, 'alice', 'alpha') == ('convert_shared', 'object-id')
    with pytest.raises(ValueError):
        store.claim(plan, 'alice', 'alpha')


def test_expired_plan(tmp_path):
    store = Store(tmp_path / 'state.db')
    plan = store.plan('alice', 'alpha', 'block_signin', 'object-id')['plan_id']
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE plans SET expires=?', (time.time() - 1,))
    with pytest.raises(ValueError):
        store.claim(plan, 'alice', 'alpha')


def test_concurrent_claim_executes_once(tmp_path):
    store = Store(tmp_path / 'state.db')
    plan = store.plan('alice', 'alpha', 'block_signin', 'object-id')['plan_id']
    def claim(_):
        try:
            store.claim(plan, 'alice', 'alpha')
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(claim, range(16))) == 1
