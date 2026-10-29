# o365-mcp – Microsoft 365 Cloud MCP

Erste implementierte Version eines tenantgetrennten MCP-Servers für Microsoft Graph und Exchange Online PowerShell. Eine mandantenfähige Entra-Anwendung authentifiziert sich per Zertifikat. Der jeweilige Kundenadmin erteilt die Zustimmung; spätere Aktionen laufen als Anwendung, nicht als dieser Benutzer.

## Enthaltene Funktionen

| Tool | Verhalten |
|---|---|
| `list_tenants` | Nur für den Bediener freigegebene Kundentenants mit Status (`pending`/`active`) und Herkunft (`config`/`mcp`) |
| `add_tenant` | Neuen Kunden per Domain oder Tenant-ID anlegen; liefert den Admin-Consent-Link |
| `get_consent_link` | Consent-Link erneut abrufen, z.B. nach neuen App-Berechtigungen |
| `verify_tenant` | Zustimmung prüfen und Kunden aktivieren |
| `set_tenant_writes` | Schreibzugriff für einen im MCP angelegten Kunden ein-/ausschalten (mit Bestätigung) |
| `remove_tenant` | Im MCP angelegten Kunden entfernen (mit Bestätigung); ändert nichts beim Kunden |
| `list_users` | Benutzer, Kontostatus und zugewiesene Lizenz-IDs; erste 1–999 Einträge |
| `get_user` | Einzelbenutzer mit Kontostatus, Lizenzen und Nutzungsland |
| `list_groups` | Gruppen; erste 1–999 Einträge |
| `list_group_members` | Mitglieder einer Gruppe; begrenzte erste Seite |
| `list_user_teams` | Teams-Mitgliedschaften eines Benutzers |
| `list_licenses` | Abonnierte Lizenz-SKUs und Verbrauch |
| `list_mailboxes` | Erste maximal 100 Exchange-Postfächer |
| `get_mailbox` | Einzelnes Postfach über Entra-Objekt-ID oder SMTP-Adresse (auch freigegebene Postfächer und Räume) |
| `find_user_files` | Dateien im OneDrive eines Benutzers nach Namen suchen (durchläuft die Ordner, da die Graph-Suche App-Zugriff nicht unterstützt) |
| `list_user_folder` | Einen Ordner im OneDrive eines Benutzers auflisten |
| `prepare_file_share` | Plan, eine Datei aus einem OneDrive mit einem Benutzer desselben Tenants zu teilen (ohne Einladungsmail) |
| `get_mailbox_permissions` | Vollzugriff, Senden-als und Kalenderberechtigungen eines Postfachs (Standardkalender oder bestimmter Kalenderordner) |
| `find_calendar_folders` | Kalenderordner nach Namen in allen Benutzer-, freigegebenen und Raumpostfächern suchen |
| `prepare_mailbox_permission` | Plan zum Vergeben/Entfernen von Vollzugriff (mit Automapping), Senden-als oder Kalenderrecht (Reviewer, Author, Editor) |
| `prepare_change` | Änderungsplan für `block_signin`, `revoke_sessions` oder `convert_shared` |
| `list_auth_methods` | Registrierte Anmelde-/MFA-Methoden eines Benutzers (nur Typ und ID, keine Telefonnummern) |
| `prepare_password_reset` | Plan für einen Passwort-Reset; das neue Zufallspasswort (16 Zeichen) wird erst bei `execute_plan` erzeugt, einmal ausgegeben und nie gespeichert |
| `prepare_mfa_reset` | Plan, alle löschbaren MFA-Methoden zu entfernen (z.B. nach Handywechsel); der Benutzer registriert sich bei der nächsten Anmeldung neu |
| `prepare_license_change` | Plan zum Zuweisen/Entfernen direkter Benutzerlizenzen |
| `prepare_distribution_membership` | Plan zum Hinzufügen/Entfernen eines Benutzers in einer Cloud-Verteilerliste (über Exchange) |
| `prepare_group_membership` | Plan zum Hinzufügen/Entfernen eines Benutzers in einer statischen Cloud-Gruppe |
| `execute_plan` | Einmalige Ausführung nach Bestätigung; Plan verfällt nach zehn Minuten |
| `get_audit_log` | Audit-Log der freigegebenen Tenants, neueste zuerst; Filter nach Tenant, Aktion, Stunden |
| `get_app_certificate` | Öffentliches App-Zertifikat (PEM, SHA-1-Fingerabdruck, Gültigkeit) für den Upload in Entra |
| `get_version` | Version und Build-Commit |

Passwort- und MFA-Reset sind nur für Cloud-Benutzer möglich (keine synchronisierten Konten, keine Gäste). Passwörter von Administratorkonten kann die Rolle User Administrator nur eingeschränkt zurücksetzen (Microsoft-Doku „Who can reset passwords“). Das neue Passwort steht ausschließlich im Ergebnis von `execute_plan`; es wird weder im Plan noch im Audit-Log gespeichert. Beim MFA-Reset wird jede Methode einzeln gelöscht und im Ergebnis ausgewiesen; schlägt eine fehl, steht der Plan im Audit-Log auf `partial`.

Keine Benutzeranlage/-löschung, vollständige On-/Offboarding-Automatik, Teams-Telefonie oder frei ausführbaren Graph-/PowerShell-Kommandos. Lizenzänderungen beziehen sich auf direkte Benutzerlizenzen. Neu zugewiesene SKUs aktivieren alle Servicepläne; gruppenbasierte Lizenzen werden nicht entfernt. Dynamische, synchronisierte, rollenfähige und Exchange-verwaltete Gruppen sind für Mitgliedschaftsänderungen ausgeschlossen. `block_signin` sperrt zukünftige Anmeldungen; es widerruft keine bestehenden Sitzungen. Große Inventare werden ausdrücklich als begrenzte erste Seite ausgewiesen; diese Version implementiert keinen vollständigen Export.

Schreibzugriff ist in der Beispielkonfiguration abgeschaltet. Für den ersten Test ausschließlich einen ausgewählten Testtenant freigeben.

## 1. Entra-Anwendung und Zertifikat

1. Im eigenen Entra-Tenant eine App registrieren: Konten in beliebigen Organisationsverzeichnissen, keine privaten Microsoft-Konten. Application-/Client-ID notieren.
2. Zertifikat: Der Dienst erzeugt beim ersten Start selbst ein RSA-3072-Zertifikat (zwei Jahre gültig) im Volume unter `/data/certificate/`. Der private Schlüssel verlässt den Container nicht. Mit dem Tool `get_app_certificate` den öffentlichen Teil (PEM) abrufen, als `.cer` speichern und in Entra unter **Certificates & secrets → Certificates** hochladen. Der angezeigte SHA-1-Fingerabdruck muss mit dem in Entra übereinstimmen. Wer ein eigenes PFX verwenden will, setzt `CERTIFICATE_PATH` und `CERTIFICATE_PASSWORD_FILE`.
3. Für Graph **Application permissions**, keine delegierten Berechtigungen, konfigurieren:

| Funktion | Anwendungsberechtigung |
|---|---|
| Benutzer lesen | `User.Read.All` |
| Gruppen lesen | `Group.Read.All` |
| Lizenzbestand lesen | `LicenseAssignment.Read.All` |
| Kunden prüfen (`verify_tenant`) | `Organization.Read.All` |
| Anmeldung sperren, optional | Zusätzlich `User.EnableDisableAccount.All` |
| Direkte Benutzerlizenzen ändern, optional | Zusätzlich `LicenseAssignment.ReadWrite.All` |
| Gruppenmitgliedschaft ändern, optional | Zusätzlich `GroupMember.ReadWrite.All` |
| Teams-Mitgliedschaften lesen, optional | `Team.ReadBasic.All` |
| OneDrive-Dateien suchen und teilen, optional | `Files.ReadWrite.All` (Zugriff auf alle Dateien des Tenants) |
| Sitzungen widerrufen, optional | `User.RevokeSessions.All` |
| Passwort zurücksetzen, optional | `User-PasswordProfile.ReadWrite.All` **und** beim Kunden die Entra-Rolle **User Administrator** (Benutzeradministrator) für die Enterprise-App |
| MFA-Methoden lesen/zurücksetzen, optional | `UserAuthenticationMethod.ReadWrite.All` (nur lesen: `UserAuthenticationMethod.Read.All`) |

Nur benötigte Rechte konfigurieren. Änderungen an privilegierten Administratorkonten unterliegen zusätzlichen Microsoft-Einschränkungen; ein erfolgreiches Consent bedeutet nicht, dass jede Kontosperrung zulässig ist.

4. Für Exchange unter **Office 365 Exchange Online → Application permissions** `Exchange.ManageAsApp` hinzufügen.
5. Jeder Kunde muss der Anwendung mit einem ausreichend berechtigten Admin zustimmen. Eine Zustimmung ausschließlich im eigenen Tenant reicht nicht. Ein tenantgebundener Admin-Consent-Link hat beispielsweise die Form:

```text
https://login.microsoftonline.com/KUNDEN-TENANT-ID/adminconsent?client_id=APP-CLIENT-ID&redirect_uri=URLENCODED_REGISTERED_REDIRECT_URI&state=RANDOM_STATE
```

Diesen Link erzeugt das Tool `add_tenant` (siehe Abschnitt 2a). Als Redirect dient die statische Seite `https://MCP_PUBLIC_HOST/consent-done` des Dienstes. Sie muss in der App-Registrierung unter **Authentication → Web → Redirect URIs** eingetragen sein. Die Seite wertet keine Parameter aus und übernimmt keine Tenant-ID aus dem Callback; ob die Zustimmung tatsächlich erteilt wurde, prüft erst `verify_tenant` mit einer echten App-Anmeldung im Kundentenant. Kein Kunden-Admin-Passwort gehört in den MCP.

6. **Zusätzlich Exchange autorisieren:** `Exchange.ManageAsApp` und Admin-Consent allein reichen für Cmdlets nicht. Dem **Service Principal der Enterprise Application beim Kunden** muss ein unterstütztes Exchange-Rollenmodell zugewiesen werden. Die Objekt-ID dieser Enterprise App unterscheidet sich von der Client-ID und von der Objekt-ID der App-Registrierung.

Microsoft dokumentiert Entra-Rollen und benutzerdefinierte Exchange-Rollengruppen für App-only PowerShell. Für einen begrenzten Test ist die Entra-Rolle **Exchange Administrator** ein funktionaler, aber weitreichender Weg. Für den Produktivbetrieb eine passende benutzerdefinierte Exchange-Rollengruppe gemäß der aktuellen Microsoft-Anleitung verwenden und `Get-EXOMailbox` sowie `Set-Mailbox -Type Shared` mit dem Service Principal testen. Diese Version weist keine Rollen automatisch zu und behauptet keine Postfach-Scope-Isolation: Der tatsächliche Zugriff ergibt sich aus den Microsoft-Rollen und Berechtigungen. Entra-Rollen dürfen engere Exchange-Zuweisungen nicht unbeabsichtigt erweitern.

Referenzen:

- https://learn.microsoft.com/en-us/exchange/permissions-exo/app-only-auth-powershell-v2
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://learn.microsoft.com/en-us/graph/api/user-update
- https://learn.microsoft.com/en-us/microsoft-365/admin/email/convert-user-mailbox-to-shared-mailbox

Vor Ablauf ein neues Zertifikat erzeugen (Dateien in `/data/certificate/` entfernen und Container neu starten), in Entra hochladen und das alte erst danach entfernen.

## 2. Kunden und Bediener konfigurieren

Die gesamte Konfiguration steht als JSON in der Stack-Variable `TENANTS_JSON` (Aufbau wie `config/tenants.example.json`). Alternativ liest der Dienst eine Datei unter `CONFIG_PATH`.

```bash
python scripts/create-client-token.py
```

Das Script zeigt einen zufälligen geheimen Bearer-Token und dessen SHA-256-Hash. Nur den Hash in `token_sha256` eintragen. Den Token im Secret Store des MCP-Clients aufbewahren. Für jeden Bediener einen eigenen Token und eindeutigen Namen verwenden.

Felder:

- `client_id`: ID der eigenen mandantenfähigen App. Darf leer bleiben, solange die App noch nicht existiert; Microsoft-Aufrufe schlagen dann kontrolliert fehl.
- `tenants[].alias`: eindeutiger Kundenalias, beispielsweise `kunde-a`.
- `tenants[].tenant_id`: verifizierte Kunden-Tenant-UUID.
- `tenants[].organization`: ursprüngliche Kunden-Domain `xyz.onmicrosoft.com`, keine frei wählbare Maildomain.
- `tenants[].writes`: pro Kunde zunächst `false`.
- `clients[].tenants`: für diesen Bediener freigegebene Aliase.
- `clients[].can_write`: zusätzlich erforderliche Schreibfreigabe des Bedieners.
- `clients[].can_manage_tenants`: darf Kunden über die MCP-Tools anlegen, prüfen und entfernen (Standard `false`).

Kunden lassen sich entweder hier in `TENANTS_JSON` fest eintragen oder zur Laufzeit über die Tools aus Abschnitt 2a anlegen. Fest eingetragene Kunden sind über die Tools nicht änderbar.

Beide Schreibflags müssen `true` sein, damit Änderungen möglich sind. Die Konfiguration wird beim Start geladen; nach Änderungen den Stack neu deployen. Nur **eine Instanz** mit diesem SQLite-Volume betreiben.

## 2a. Kunden über den MCP hinzufügen

Voraussetzung: Der Bediener hat `can_manage_tenants: true`, die App-Registrierung existiert (`client_id` gesetzt, Zertifikat hochgeladen) und `https://MCP_PUBLIC_HOST/consent-done` ist in der App als Web-Redirect-URI eingetragen.

1. `add_tenant(alias="kunde-a", domain="kunde-a.example")` – die Tenant-ID wird über die öffentlichen Microsoft-Metadaten der Domain ermittelt (alternativ `tenant_id` direkt angeben). Der Kunde wird mit Status `pending` gespeichert und dem anlegenden Bediener freigegeben. Schreibzugriff ist aus.
2. Den zurückgegebenen `consent_url` im Browser öffnen, mit dem eigenen Admin-Konto **dieses** Kundentenants anmelden und zustimmen.
3. `verify_tenant(tenant="kunde-a")` – meldet sich als App im Kundentenant an, gleicht die Tenant-ID ab, speichert die ursprüngliche `onmicrosoft.com`-Domain und setzt den Status auf `active`. Direkt nach der Zustimmung kann es einige Minuten dauern.
4. Für Postfach-Tools beim Kunden der Enterprise-Anwendung eine Exchange-Rolle zuweisen (Abschnitt 1, Punkt 6).
5. Optional `set_tenant_writes(tenant="kunde-a", enabled=true, confirmed=true)`.

Die Kunden liegen in der SQLite-Datenbank im Volume `data`; ein Redeploy ist nicht nötig. `remove_tenant` entfernt den Kunden nur aus dem MCP. Um den Zugriff in Microsoft zu entziehen, beim Kunden die Enterprise-Anwendung löschen.

## 3. Image

GitHub Actions (`.github/workflows/docker-publish.yml`) testet und baut bei jedem Push auf `main` das Image `ghcr.io/kdt-solutions/o365-mcp` (Tags `latest` und `sha-<commit>`). Vor dem Push laufen die Unit-Tests und ein Smoke-Test im fertigen Container. Version, Commit und Build-Datum liefert das Tool `get_version`.

Das Image enthält Python 3.12, PowerShell 7.4 und ExchangeOnlineManagement 3.9.0, nur für amd64.

## 4. Daten

Es werden keine Dateien auf dem Docker-Host benötigt. Das benannte Volume `data` enthält Pläne, Audit-Log, die über den MCP angelegten Kunden und das App-Zertifikat. Für Backups SQLite-kompatible Backups oder einen gestoppten Dienst verwenden. Das Audit enthält Kunden- und Zielobjekt-IDs.

Audit: ein Eintrag pro Aufruf mit Ergebnis und Dauer (`duration_ms`); schreibende Aktionen zusätzlich mit einem `executing`-Eintrag vor dem Remote-Aufruf. Einträge älter als `AUDIT_RETENTION_DAYS` (Standard 365, `0` = unbegrenzt) und abgelaufene Pläne werden stündlich gelöscht.

## 5. Portainer-Stack

Portainer **Stacks → Add stack → Repository**, Docker Standalone:

- Repository URL: `https://github.com/KDT-Solutions/o365-mcp`
- Repository reference: `refs/heads/main`
- Compose path: `docker-compose.yml`

Stack-Variablen:

| Variable | Bedeutung |
|---|---|
| `TENANTS_JSON` | Konfiguration (Pflicht) |
| `MCP_BIND_ADDR` | Host-IP, auf die der Reverse-Proxy zugreift, z.B. `192.0.2.10` |
| `MCP_HOST_PORT` | Host-Port, Standard `8437` |
| `MCP_PUBLIC_HOST` | Öffentlicher Hostname, Standard `mcp.example.com` |
| `MCP_PATH` | MCP-Endpunkt, Standard `/o365` |

| `AUDIT_RETENTION_DAYS` | Aufbewahrung Audit, Standard `365` |
| `EXCHANGE_MAX_SESSIONS` | Gleichzeitige Exchange-Sitzungen, Standard `2` |
| `EXCHANGE_IDLE_SECONDS` | Leerlauf bis zum Schliessen einer Exchange-Sitzung, Standard `600` |

Nach einem neuen Image den Stack mit **Pull and redeploy** aktualisieren.

Der Reverse-Proxy (Nginx Proxy Manager) leitet `https://mcp.example.com` an `http://MCP_BIND_ADDR:MCP_HOST_PORT` weiter und muss den Host- und Authorization-Header durchreichen. Der Dienst prüft den Host-Header gegen `MCP_PUBLIC_HOST`.

`/healthz` prüft nur, ob der HTTP-Dienst läuft; es führt keinen Microsoft-Login aus. `/healthz` und `/consent-done` sind ohne Bearer-Token erreichbar; beide geben nur statische Inhalte aus.

### Exchange-Sitzungen

Pro Kundentenant läuft eine dauerhafte PowerShell-Sitzung, die nach dem ersten Aufruf verbunden bleibt. Weitere Aufrufe sparen Prozessstart und Anmeldung. Sitzungen werden nach `EXCHANGE_IDLE_SECONDS` Leerlauf und spätestens nach 45 Minuten geschlossen und beim nächsten Aufruf neu aufgebaut. Höchstens `EXCHANGE_MAX_SESSIONS` Sitzungen gleichzeitig; bei Bedarf wird die am längsten unbenutzte geschlossen. Bricht ein Aufruf ab (Timeout 180 s), wird die Sitzung verworfen und nicht wiederverwendet.

## 6. MCP-Client verbinden

Für Clients mit Streamable HTTP und eigenen Authorization-Headern:

```json
{
  "mcpServers": {
    "m365": {
      "type": "http",
      "url": "https://mcp.example.com/o365",
      "headers": { "Authorization": "Bearer DEIN_GEHEIMER_CLIENT_TOKEN" }
    }
  }
}
```

Das genaue Konfigurationsformat hängt vom Client ab. Diese Version implementiert **Bearer-Authentifizierung, keinen OAuth-Authorization-Server** und keine OAuth-Discovery. Eine direkte ChatGPT-Anbindung, die OAuth erwartet und keine eigenen Header erlaubt, ist damit noch nicht abgedeckt. Dafür ist eine zusätzliche kompatible OAuth-Schicht mit Audience-Prüfung und Bedienerzuordnung erforderlich. Die Microsoft-App-Authentifizierung bleibt davon unabhängig.

## 7. Test und Änderungen

Zuerst `list_tenants`, `list_users` und `get_mailbox` im Testtenant ausführen. Prüfen, dass ein nicht freigegebener Alias abgewiesen wird. Danach bei Bedarf beide Schreibflags aktivieren und den Dienst neu starten.

Beispielablauf für ein Testpostfach:

1. `prepare_change(tenant="kunde-a", action="convert_shared", user_id="ENTRA-USER-UUID")` aufrufen.
2. Angezeigten Kunden und Benutzer prüfen. Hybridbetrieb, Postfachgröße, Archiv, Aufbewahrung und erforderliche Lizenzen separat prüfen.
3. Nach ausdrücklicher Freigabe `execute_plan(tenant="kunde-a", plan_id="...", confirmed=true)` aufrufen.
4. Mit `get_mailbox` den resultierenden Typ nachlesen. Die Konvertierung entfernt keine Lizenzen und ist kein vollständiges Offboarding.

Die Bestätigung ist ein Toolparameter und keine unabhängige menschliche Freigabeinstanz. Ein Client mit Schreibrechten kann sie selbst setzen. Für eine technisch erzwungene Vier-Augen-Freigabe wäre ein separater Freigabekanal mit eigener Identität nötig.

Pläne sind an Bediener und Tenant gebunden und werden vor dem Remote-Aufruf atomar verbraucht. Bei Timeout oder Fehler kann Microsoft die Aktion trotzdem ausgeführt haben. Deshalb wird derselbe Plan nicht erneut ausgeführt; zuerst den tatsächlichen Zustand lesen. Mehrstufige Operationen sind nicht enthalten.

## Lokale Tests

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install pytest
.venv/bin/pytest -q
```

Die Tests prüfen HTTP-MCP, Authentifizierung, Host-Prüfung, Kundentrennung, Bestätigung, Ablauf und gleichzeitige Verwendung eines Plans mit simulierten Providern. Microsoft-Integration braucht echte App-Registrierung, Zertifikat, Kundenzustimmung und einen Testtenant. Der Quellcode allein richtet diese nicht ein.

## Erweiterungsumfang

Die gewünschte breite Verwaltung ist in `FUNKTIONSUMFANG.md` abgegrenzt. App-only-Zugriff unterstützt nicht automatisch jede Funktion jeder Microsoft-Admin-Konsole. Insbesondere Teams-Telefonie muss pro Cmdlet und Telefonie-Modell geprüft werden.
