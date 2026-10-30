"""Read-only security views (sign-ins, audit, Identity Protection, inbox rules) and the risk actions.

Every function takes fixed, validated parameters and builds its Graph request itself; callers never pass
URLs, filters or OData expressions. Results are reduced to the fields an administrator needs to judge
whether an account is compromised.
"""
import time
import uuid
from collections import Counter
from datetime import datetime, timezone


RISK_ACTIONS = ('dismiss_risk', 'confirm_compromised')


def since_iso(hours):
    if type(hours) is not int or not 1 <= hours <= 720:
        raise ValueError('hours must be between 1 and 720 (30 days)')
    moment = datetime.fromtimestamp(time.time() - hours * 3600, timezone.utc)
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def bounded(limit, maximum=1000):
    if type(limit) is not int or not 1 <= limit <= maximum:
        raise ValueError(f'limit must be between 1 and {maximum}')
    return limit


def sign_in_entry(item):
    status = item.get('status') or {}
    location = item.get('location') or {}
    device = item.get('deviceDetail') or {}
    return {
        'time': item.get('createdDateTime'),
        'app': item.get('appDisplayName'),
        'resource': item.get('resourceDisplayName'),
        'ip': item.get('ipAddress'),
        'city': location.get('city'),
        'country': location.get('countryOrRegion'),
        'error_code': status.get('errorCode'),
        'failure_reason': status.get('failureReason') if status.get('errorCode') else None,
        'client_app': item.get('clientAppUsed'),
        'os': device.get('operatingSystem'),
        'browser': device.get('browser'),
        'device_compliant': device.get('isCompliant'),
        'conditional_access': item.get('conditionalAccessStatus'),
        'risk_level': item.get('riskLevelDuringSignIn'),
        'risk_state': item.get('riskState'),
        'cross_tenant': item.get('crossTenantAccessType'),
        'resource_tenant_id': item.get('resourceTenantId'),
        'request_id': item.get('id'),
    }


def summarize(entries):
    """Distinct IPs, countries and failures so unusual sign-ins stand out without reading every row."""
    ips = Counter(e['ip'] for e in entries if e['ip'])
    countries = Counter(e['country'] for e in entries if e['country'])
    failures = Counter(f"{e['error_code']} {e['failure_reason'] or ''}".strip() for e in entries if e['error_code'])
    places = {}
    for e in entries:
        if e['ip'] and e['ip'] not in places:
            places[e['ip']] = ', '.join(p for p in (e['city'], e['country']) if p) or None
    return {'sign_ins': len(entries),
            'countries': dict(countries.most_common()),
            'ip_addresses': [{'ip': ip, 'count': n, 'location': places.get(ip)} for ip, n in ips.most_common(50)],
            'failures': dict(failures.most_common(20)),
            'risky': sum(1 for e in entries if e['risk_level'] not in (None, 'none', 'hidden'))}


async def sign_ins(graph, tenant, user_id, hours, interactive, failures_only, limit):
    user_id = str(uuid.UUID(user_id))
    query = f"userId eq '{user_id}' and createdDateTime ge {since_iso(hours)}"
    if failures_only:
        query += ' and status/errorCode ne 0'
    if interactive:
        params, api = {'$filter': query, '$top': '500'}, 'v1.0'
    else:
        # Non-interactive sign-ins (token refreshes of Outlook, Teams, OneDrive ...) exist only in beta.
        params = {'$filter': query + " and signInEventTypes/any(t: t eq 'nonInteractiveUser')", '$top': '500'}
        api = 'beta'
    items, more = await graph.collect(tenant, 'auditLogs/signIns', params, bounded(limit), api=api)
    entries = [sign_in_entry(i) for i in items]
    return {'user_id': user_id, 'interactive': interactive, 'hours': hours, 'summary': summarize(entries),
            'items': entries, 'more_available': more}


async def directory_audits(graph, tenant, user_id, hours, limit):
    params = {'$filter': f'activityDateTime ge {since_iso(hours)}', '$top': '500'}
    if user_id:
        user_id = str(uuid.UUID(user_id))
        params['$filter'] += f" and targetResources/any(t: t/id eq '{user_id}')"
    items, more = await graph.collect(tenant, 'auditLogs/directoryAudits', params, bounded(limit))
    entries = []
    for item in items:
        initiated = item.get('initiatedBy') or {}
        by = (initiated.get('user') or {}).get('userPrincipalName') or (initiated.get('app') or {}).get('displayName')
        entries.append({'time': item.get('activityDateTime'), 'activity': item.get('activityDisplayName'),
                        'category': item.get('category'), 'result': item.get('result'), 'initiated_by': by,
                        'targets': [t.get('userPrincipalName') or t.get('displayName') for t in item.get('targetResources', [])]})
    return {'user_id': user_id, 'hours': hours, 'items': entries, 'more_available': more}


def risky_user_entry(item):
    return {'id': item.get('id'), 'user': item.get('userPrincipalName'), 'name': item.get('userDisplayName'),
            'risk_level': item.get('riskLevel'), 'risk_state': item.get('riskState'), 'risk_detail': item.get('riskDetail'),
            'last_updated': item.get('riskLastUpdatedDateTime'), 'deleted': item.get('isDeleted')}


async def risky_users(graph, tenant, at_risk_only, limit):
    params = {'$top': '500'}
    if at_risk_only:
        params['$filter'] = "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"
    items, more = await graph.collect(tenant, 'identityProtection/riskyUsers', params, bounded(limit, 500))
    return {'items': [risky_user_entry(i) for i in items], 'more_available': more,
            'notice': 'Without Entra ID P2 Microsoft hides risk levels and detection details (shown as hidden/none).'}


async def risky_user(graph, tenant, user_id):
    user_id = str(uuid.UUID(user_id))
    try:
        current = await graph.request(tenant, f'identityProtection/riskyUsers/{user_id}')
    except RuntimeError as error:
        if 'HTTP 404' not in str(error):
            raise
        current = None
    history = await graph.request(tenant, f'identityProtection/riskyUsers/{user_id}/history')
    return {'user_id': user_id, 'listed': current is not None,
            'current': risky_user_entry(current) if current else None,
            'history': [{'time': h.get('riskLastUpdatedDateTime'), 'risk_level': h.get('riskLevel'), 'risk_state': h.get('riskState'),
                         'risk_detail': h.get('riskDetail'), 'activity': (h.get('activity') or {}).get('eventTypes'),
                         'initiated_by': h.get('initiatedBy')} for h in history.get('value', [])[:50]],
            'notice': 'Not listed means Identity Protection holds no risk record for this user in this tenant.'}


async def risk_detections(graph, tenant, user_id, hours, limit):
    params = {'$filter': f'detectedDateTime ge {since_iso(hours)}', '$top': '500'}
    if user_id:
        params['$filter'] += f" and userId eq '{str(uuid.UUID(user_id))}'"
    items, more = await graph.collect(tenant, 'identityProtection/riskDetections', params, bounded(limit, 500))
    entries = [{'time': i.get('detectedDateTime'), 'user': i.get('userPrincipalName'), 'type': i.get('riskEventType'),
                'level': i.get('riskLevel'), 'state': i.get('riskState'), 'detail': i.get('riskDetail'),
                'timing': i.get('detectionTimingType'), 'ip': i.get('ipAddress'),
                'city': (i.get('location') or {}).get('city'), 'country': (i.get('location') or {}).get('countryOrRegion'),
                'source': i.get('source'), 'request_id': i.get('requestId')} for i in items]
    return {'hours': hours, 'items': entries, 'more_available': more}


async def inbox_rules(graph, tenant, user_id):
    """Inbox rules are the classic place where attackers hide forwarding or deletion of mail."""
    user_id = str(uuid.UUID(user_id))
    data = await graph.request(tenant, f'users/{user_id}/mailFolders/inbox/messageRules')
    rules = []
    for rule in data.get('value', []):
        actions = rule.get('actions') or {}
        forwards = [r.get('emailAddress', {}).get('address') for key in ('forwardTo', 'redirectTo', 'forwardAsAttachmentTo')
                    for r in actions.get(key) or []]
        rules.append({'name': rule.get('displayName'), 'enabled': rule.get('isEnabled'), 'sequence': rule.get('sequence'),
                      'conditions': {k: v for k, v in (rule.get('conditions') or {}).items() if v},
                      'forwards_to': forwards, 'deletes': bool(actions.get('delete') or actions.get('permanentDelete')),
                      'moves_to_folder': actions.get('moveToFolder'), 'marks_read': actions.get('markAsRead'),
                      'stops_processing': actions.get('stopProcessingRules')})
    suspicious = [r['name'] for r in rules if r['forwards_to'] or r['deletes']]
    return {'user_id': user_id, 'rules': rules, 'forwarding_or_deleting_rules': suspicious}


async def mailbox_forwarding(graph, tenant, user_id):
    """Automatic replies and forwarding visible through Graph mailbox settings."""
    user_id = str(uuid.UUID(user_id))
    settings = await graph.request(tenant, f'users/{user_id}/mailboxSettings')
    reply = settings.get('automaticRepliesSetting') or {}
    return {'user_id': user_id, 'automatic_replies': reply.get('status'),
            'delegate_meeting_messages': settings.get('delegateMeetingMessageDeliveryOptions'),
            'notice': 'SMTP forwarding set by an administrator (ForwardingSmtpAddress) is only visible via Exchange (get_mailbox).'}


async def risk_action(graph, tenant, action, user_id):
    user_id = str(uuid.UUID(user_id))
    if action not in RISK_ACTIONS:
        raise ValueError('Unsupported risk action')
    path = 'identityProtection/riskyUsers/dismiss' if action == 'dismiss_risk' else 'identityProtection/riskyUsers/confirmCompromised'
    await graph.request(tenant, path, body={'userIds': [user_id]}, method='POST')
    return {'user_id': user_id, 'action': action, 'done': True}
