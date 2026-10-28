import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from m365_mcp.certs import certificate_info, ensure_certificate
from m365_mcp.core import Registry, Store, Tenant
from m365_mcp.providers import Exchange

FAKE_PWSH = '''#!{python}
import json, os, sys
log = os.environ['FAKE_PWSH_LOG']
settings = json.loads(sys.stdin.readline())
with open(log, 'a') as handle:
    handle.write('connect ' + settings['organization'] + '\\n')
print('WARNING: module noise without marker', flush=True)
print('@@M365@@' + json.dumps({{'ok': True}}), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    with open(log, 'a') as handle:
        handle.write('call ' + request['action'] + '\\n')
    if request['target'] == '00000000-0000-0000-0000-00000000dead':
        print('@@M365@@' + json.dumps({{'ok': False}}), flush=True)
        continue
    print('@@M365@@' + json.dumps({{'ok': True, 'result': [{{'org': settings['organization']}}]}}), flush=True)
'''


def fake_exchange(tmp_path, monkeypatch, **options):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    pwsh = bin_dir / 'pwsh'
    pwsh.write_text(FAKE_PWSH.format(python=sys.executable))
    pwsh.chmod(pwsh.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv('PATH', f'{bin_dir}{os.pathsep}{os.environ["PATH"]}')
    monkeypatch.setenv('FAKE_PWSH_LOG', str(tmp_path / 'log'))
    return Exchange('00000000-0000-0000-0000-000000000001', 'cert.pfx', 'password', 'script.ps1', **options), tmp_path / 'log'


def tenant(alias, index):
    return Tenant(alias, f'00000000-0000-0000-0000-00000000000{index}', f'{alias}.onmicrosoft.com')


def test_exchange_session_is_reused_per_tenant(tmp_path, monkeypatch):
    exchange, log = fake_exchange(tmp_path, monkeypatch)
    alpha = tenant('alpha', 2)

    async def scenario():
        first = await exchange.run(alpha, 'list_mailboxes')
        second = await exchange.run(alpha, 'list_mailboxes')
        failed = None
        try:
            await exchange.run(alpha, 'get_mailbox', '00000000-0000-0000-0000-00000000dead')
        except RuntimeError as error:
            failed = error
        third = await exchange.run(alpha, 'get_mailbox', '00000000-0000-0000-0000-000000000005')
        for key in list(exchange.sessions):
            await exchange.discard(key)
        exchange.reaper.cancel()
        return first, second, failed, third

    first, second, failed, third = asyncio.run(scenario())
    assert first == second == third == [{'org': 'alpha.onmicrosoft.com'}]
    assert failed is not None
    lines = log.read_text().splitlines()
    assert lines.count('connect alpha.onmicrosoft.com') == 1
    assert len([line for line in lines if line.startswith('call ')]) == 4


def test_exchange_evicts_least_recently_used_session(tmp_path, monkeypatch):
    exchange, log = fake_exchange(tmp_path, monkeypatch, max_sessions=1)

    async def scenario():
        await exchange.run(tenant('alpha', 2), 'list_mailboxes')
        result = await exchange.run(tenant('beta', 3), 'list_mailboxes')
        keys = list(exchange.sessions)
        for key in keys:
            await exchange.discard(key)
        exchange.reaper.cancel()
        return result, keys

    result, keys = asyncio.run(scenario())
    assert result == [{'org': 'beta.onmicrosoft.com'}]
    assert keys == ['00000000-0000-0000-0000-000000000003']


def test_audit_log_filters_and_retention(tmp_path):
    store = Store(tmp_path / 'state.db', retention_days=30)
    store.audit('alice', 'alpha', 'list_users', '', 'succeeded', 12)
    store.audit('alice', 'beta', 'list_users', '', 'succeeded', 5)
    store.audit('alice', 'alpha', 'get_user', 'x', 'failed', 7)
    rows = store.audit_log(['alpha'])
    assert [row['action'] for row in rows] == ['get_user', 'list_users']
    assert rows[1]['duration_ms'] == 12
    assert [row['tenant'] for row in store.audit_log(['alpha'], action='list_users')] == ['alpha']
    assert store.audit_log([]) == []
    import sqlite3
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE audit SET at=? WHERE tenant=?', (time.time() - 31 * 86400, 'beta'))
    store.purge()
    assert store.audit_log(['beta']) == []


def test_registry_from_env_text_without_app_or_tenants():
    text = json.dumps({'tenants': [], 'clients': [{'name': 'kim', 'token_sha256': hashlib.sha256(b't').hexdigest(), 'tenants': []}]})
    registry = Registry(text=text)
    assert registry.client_id is None
    assert registry.authenticate('t')['name'] == 'kim'


def test_certificate_is_generated_once_with_private_permissions(tmp_path):
    pfx, password = ensure_certificate(tmp_path / 'certificate')
    assert ensure_certificate(tmp_path / 'certificate') == (pfx, password)
    assert stat.S_IMODE(Path(pfx).stat().st_mode) == 0o600
    info = certificate_info(pfx, password)
    assert info['pem'].startswith('-----BEGIN CERTIFICATE-----')
    assert 'PRIVATE' not in info['pem']
    assert len(info['thumbprint_sha1']) == 40
