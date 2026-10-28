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
    def __init__(self, path=None, text=None):
        config = json.loads(text if text is not None else Path(path).read_text())
        # client_id may stay empty until the Entra app exists; Microsoft calls then fail closed.
        self.client_id = str(uuid.UUID(config['client_id'])) if config.get('client_id') else None
        self.tenants = {}
        for item in config.get('tenants', []):
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
    def __init__(self, path, retention_days=365):
        self.path = path
        self.retention = retention_days * 86400
        self.purged = 0.0
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, actor TEXT, tenant TEXT, action TEXT, target TEXT, expires REAL, status TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS audit (at REAL, actor TEXT, tenant TEXT, action TEXT, target TEXT, outcome TEXT, duration_ms INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS plan_payloads (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS audit_at ON audit (at)')
            db.execute('CREATE INDEX IF NOT EXISTS audit_tenant_at ON audit (tenant, at)')
        self.purge()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute('PRAGMA synchronous=NORMAL')
        return db

    def purge(self):
        """Drop audit rows past retention and plans that expired more than a day ago."""
        now = time.time()
        with self.connect() as db:
            if self.retention > 0:
                db.execute('DELETE FROM audit WHERE at < ?', (now - self.retention,))
            db.execute('DELETE FROM plan_payloads WHERE id IN (SELECT id FROM plans WHERE expires < ?)', (now - 86400,))
            db.execute('DELETE FROM plans WHERE expires < ?', (now - 86400,))
        self.purged = now

    def audit(self, actor, tenant, action, target, outcome, duration_ms=None):
        if time.time() - self.purged > 3600:
            self.purge()
        with self.connect() as db:
            db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?,?)', (time.time(), actor, tenant, action, target, outcome, duration_ms))

    def audit_log(self, tenants, limit=100, action=None, since=None):
        if not tenants:
            return []
        query = f"SELECT at, actor, tenant, action, target, outcome, duration_ms FROM audit WHERE tenant IN ({','.join('?' * len(tenants))})"
        args = list(tenants)
        if action:
            query += ' AND action = ?'
            args.append(action)
        if since is not None:
            query += ' AND at >= ?'
            args.append(since)
        query += ' ORDER BY at DESC LIMIT ?'
        args.append(limit)
        with self.connect() as db:
            rows = db.execute(query, args).fetchall()
        keys = ('at', 'actor', 'tenant', 'action', 'target', 'outcome', 'duration_ms')
        return [dict(zip(keys, row)) for row in rows]

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
