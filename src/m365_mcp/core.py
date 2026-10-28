import hashlib
import json
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Tenant:
    alias: str
    tenant_id: str
    organization: str
    writes: bool = False


class Registry:
    def __init__(self, path):
        config = json.loads(Path(path).read_text())
        self.client_id = str(uuid.UUID(config['client_id']))
        self.tenants = {}
        for item in config['tenants']:
            tenant = Tenant(**item)
            uuid.UUID(tenant.tenant_id)
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', tenant.alias):
                raise ValueError('Invalid tenant alias')
            if not re.fullmatch(r'[a-zA-Z0-9-]+\.onmicrosoft\.com', tenant.organization):
                raise ValueError('Organization must be the initial onmicrosoft.com domain')
            if tenant.alias in self.tenants or type(tenant.writes) is not bool:
                raise ValueError('Duplicate alias or invalid writes flag')
            self.tenants[tenant.alias] = tenant
        self.clients = config['clients']
        if not self.clients:
            raise ValueError('At least one client required')
        for client in self.clients:
            if not re.fullmatch('[0-9a-f]{64}', client['token_sha256']):
                raise ValueError('Invalid token digest')
            if not set(client['tenants']) <= self.tenants.keys():
                raise ValueError('Unknown tenant in client ACL')
            if type(client.get('can_write', False)) is not bool:
                raise ValueError('Invalid client write flag')
        if len({c['name'] for c in self.clients}) != len(self.clients):
            raise ValueError('Client names must be unique')
        if len({c['token_sha256'] for c in self.clients}) != len(self.clients):
            raise ValueError('Client tokens must be unique')

    def authenticate(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        return next((c for c in self.clients if secrets.compare_digest(c['token_sha256'], digest)), None)

    def authorize(self, client, alias, write=False):
        if alias not in client['tenants'] or alias not in self.tenants:
            raise ValueError('Tenant access denied')
        tenant = self.tenants[alias]
        if write and not (tenant.writes and client.get('can_write', False)):
            raise ValueError('Writes disabled for client or tenant')
        return tenant


class Store:
    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, actor TEXT, tenant TEXT, action TEXT, target TEXT, expires REAL, status TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS audit (at REAL, actor TEXT, tenant TEXT, action TEXT, target TEXT, outcome TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS plan_payloads (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')

    def connect(self):
        return sqlite3.connect(self.path, timeout=15)

    def audit(self, actor, tenant, action, target, outcome):
        with self.connect() as db:
            db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)', (time.time(), actor, tenant, action, target, outcome))

    def plan(self, actor, tenant, action, target, payload=None):
        identifier = secrets.token_urlsafe(32)
        expires = time.time() + 600
        with self.connect() as db:
            db.execute('INSERT INTO plans VALUES (?,?,?,?,?,?,?)', (identifier, actor, tenant, action, target, expires, 'pending'))
            db.execute('INSERT INTO plan_payloads VALUES (?,?)', (identifier, json.dumps(payload or {})))
        return {'plan_id': identifier, 'tenant': tenant, 'action': action, 'target': target, 'expires_at': expires,
                'notice': 'Review tenant and target, then explicitly confirm using execute_plan. Expires in 10 minutes.'}

    def payload(self, identifier):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM plan_payloads WHERE id=?', (identifier,)).fetchone()
        return json.loads(row[0]) if row else {}

    def claim(self, identifier, actor, tenant):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT action,target FROM plans WHERE id=? AND actor=? AND tenant=? AND expires>? AND status='pending'", (identifier, actor, tenant, time.time())).fetchone()
            if row is None:
                raise ValueError('Plan invalid, expired, already used or belongs to another actor/tenant')
            db.execute("UPDATE plans SET status='executing' WHERE id=?", (identifier,))
            return row

    def finish(self, identifier, status):
        with self.connect() as db:
            db.execute('UPDATE plans SET status=? WHERE id=?', (status, identifier))
