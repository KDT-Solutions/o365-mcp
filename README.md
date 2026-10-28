# Microsoft 365 Cloud MCP für Portainer

Erste implementierte Version eines tenantgetrennten MCP-Servers für Microsoft Graph und Exchange Online PowerShell. Eine mandantenfähige Entra-Anwendung authentifiziert sich per Zertifikat. Der jeweilige Kundenadmin erteilt die Zustimmung; spätere Aktionen laufen als Anwendung, nicht als dieser Benutzer.

## Enthaltene Funktionen

| Tool | Verhalten |
|---|---|
| `list_tenants` | Nur für den Bediener freigegebene Kundentenants |
| `list_users` | Benutzer, Kontostatus und zugewiesene Lizenz-IDs; erste 1–999 Einträge |
| `get_user` | Einzelbenutzer mit Kontostatus, Lizenzen und Nutzungsland |
| `list_groups` | Gruppen; erste 1–999 Einträge |
| `list_group_members` | Mitglieder einer Gruppe; begrenzte erste Seite |
| `list_user_teams` | Teams-Mitgliedschaften eines Benutzers |
| `list_licenses` | Abonnierte Lizenz-SKUs und Verbrauch |
| `list_mailboxes` | Erste maximal 100 Exchange-Postfächer |
| `get_mailbox` | Einzelnes Postfach über Entra-Benutzerobjekt-ID |
| `prepare_change` | Änderungsplan für `block_signin`, `revoke_sessions` oder `convert_shared` |
| `prepare_license_change` | Plan zum Zuweisen/Entfernen direkter Benutzerlizenzen |
| `prepare_group_membership` | Plan zum Hinzufügen/Entfernen eines Benutzers in einer statischen Cloud-Gruppe |
| `execute_plan` | Einmalige Ausführung nach Bestätigung; Plan verfällt nach zehn Minuten |

Keine Benutzeranlage/-löschung, vollständige On-/Offboarding-Automatik, Teams-Telefonie oder frei ausführbaren Graph-/PowerShell-Kommandos. Lizenzänderungen beziehen sich auf direkte Benutzerlizenzen. Neu zugewiesene SKUs aktivieren alle Servicepläne; gruppenbasierte Lizenzen werden nicht entfernt. Dynamische, synchronisierte, rollenfähige und Exchange-verwaltete Gruppen sind für Mitgliedschaftsänderungen ausgeschlossen. `block_signin` sperrt zukünftige Anmeldungen; es widerruft keine bestehenden Sitzungen. Große Inventare werden ausdrücklich als begrenzte erste Seite ausgewiesen; diese Version implementiert keinen vollständigen Export.

Schreibzugriff ist in der Beispielkonfiguration abgeschaltet. Für den ersten Test ausschließlich einen ausgewählten Testtenant freigeben.

## 1. Entra-Anwendung und Zertifikat

1. Im eigenen Entra-Tenant eine App registrieren: Konten in beliebigen Organisationsverzeichnissen, keine privaten Microsoft-Konten. Application-/Client-ID notieren.
2. Ein RSA-Zertifikat erstellen oder ein verwaltetes Zertifikat verwenden. Öffentlichen Zertifikatsteil unter **Certificates & secrets → Certificates** hochladen. Privater Schlüssel bleibt beim MCP.
3. Für Graph **Application permissions**, keine delegierten Berechtigungen, konfigurieren:

| Funktion | Anwendungsberechtigung |
|---|---|
| Benutzer lesen | `User.Read.All` |
| Gruppen lesen | `Group.Read.All` |
| Lizenzbestand lesen | `LicenseAssignment.Read.All` |
| Anmeldung sperren, optional | Zusätzlich `User.EnableDisableAccount.All` |
| Direkte Benutzerlizenzen ändern, optional | Zusätzlich `LicenseAssignment.ReadWrite.All` |
| Gruppenmitgliedschaft ändern, optional | Zusätzlich `GroupMember.ReadWrite.All` |
| Teams-Mitgliedschaften lesen, optional | `Team.ReadBasic.All` |
| Sitzungen widerrufen, optional | `User.RevokeSessions.All` |

Nur benötigte Rechte konfigurieren. Änderungen an privilegierten Administratorkonten unterliegen zusätzlichen Microsoft-Einschränkungen; ein erfolgreiches Consent bedeutet nicht, dass jede Kontosperrung zulässig ist.

4. Für Exchange unter **Office 365 Exchange Online → Application permissions** `Exchange.ManageAsApp` hinzufügen.
5. Jeder Kunde muss der Anwendung mit einem ausreichend berechtigten Admin zustimmen. Eine Zustimmung ausschließlich im eigenen Tenant reicht nicht. Ein tenantgebundener Admin-Consent-Link hat beispielsweise die Form:

```text
https://login.microsoftonline.com/KUNDEN-TENANT-ID/adminconsent?client_id=APP-CLIENT-ID&redirect_uri=URLENCODED_REGISTERED_REDIRECT_URI&state=RANDOM_STATE
```

Der Redirect muss zur App-Registrierung passen und von dir kontrolliert werden. Diese Version bietet keinen automatischen Consent-Callback und übernimmt keine Tenant-ID aus einem Callback. Tenant-ID und Zustimmung anschließend unabhängig im Kundenportal verifizieren. Kein Kunden-Admin-Passwort gehört in den MCP.

6. **Zusätzlich Exchange autorisieren:** `Exchange.ManageAsApp` und Admin-Consent allein reichen für Cmdlets nicht. Dem **Service Principal der Enterprise Application beim Kunden** muss ein unterstütztes Exchange-Rollenmodell zugewiesen werden. Die Objekt-ID dieser Enterprise App unterscheidet sich von der Client-ID und von der Objekt-ID der App-Registrierung.

Microsoft dokumentiert Entra-Rollen und benutzerdefinierte Exchange-Rollengruppen für App-only PowerShell. Für einen begrenzten Test ist die Entra-Rolle **Exchange Administrator** ein funktionaler, aber weitreichender Weg. Für den Produktivbetrieb eine passende benutzerdefinierte Exchange-Rollengruppe gemäß der aktuellen Microsoft-Anleitung verwenden und `Get-EXOMailbox` sowie `Set-Mailbox -Type Shared` mit dem Service Principal testen. Diese Version weist keine Rollen automatisch zu und behauptet keine Postfach-Scope-Isolation: Der tatsächliche Zugriff ergibt sich aus den Microsoft-Rollen und Berechtigungen. Entra-Rollen dürfen engere Exchange-Zuweisungen nicht unbeabsichtigt erweitern.

Referenzen:

- https://learn.microsoft.com/en-us/exchange/permissions-exo/app-only-auth-powershell-v2
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://learn.microsoft.com/en-us/graph/api/user-update
- https://learn.microsoft.com/en-us/microsoft-365/admin/email/convert-user-mailbox-to-shared-mailbox

### Beispiel für ein Zertifikat auf dem eigenen Host

```bash
umask 077
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 \
  -keyout app.key -out app.crt -subj '/CN=m365-cloud-mcp'
openssl pkcs12 -export -inkey app.key -in app.crt -out m365.pfx
```

OpenSSL fragt Passwörter interaktiv ab. Das PFX-Exportpasswort in einer Datei `pfx_password` im Secret-Verzeichnis speichern, ohne zusätzliche Leerzeichen. `app.crt` wird in Entra hochgeladen. Den privaten Schlüssel und das PFX nicht hochladen, nicht im Chat senden und nicht ins Repository übernehmen. Zertifikatsablauf überwachen und Rotation vor Ablauf einplanen. Access-Tokens laufen ebenfalls ab; MSAL erneuert sie automatisch.

## 2. Kunden und Bediener konfigurieren

```bash
cp config/tenants.example.json config/tenants.json
python scripts/create-client-token.py
```

Das Script zeigt einen zufälligen geheimen Bearer-Token und dessen SHA-256-Hash. Nur den Hash in `token_sha256` eintragen. Den Token im Secret Store des MCP-Clients aufbewahren. Für jeden Bediener einen eigenen Token und eindeutigen Namen verwenden.

In `tenants.json` eintragen:

- `client_id`: ID der eigenen mandantenfähigen App.
- `alias`: eindeutiger Kundenalias, beispielsweise `kunde-a`.
- `tenant_id`: verifizierte Kunden-Tenant-UUID.
- `organization`: ursprüngliche Kunden-Domain `xyz.onmicrosoft.com`, keine frei wählbare Maildomain.
- `writes`: pro Kunde zunächst `false`.
- `clients[].tenants`: für diesen Bediener freigegebene Aliase.
- `clients[].can_write`: zusätzlich erforderliche Schreibfreigabe des Bedieners.

Beide Schreibflags müssen `true` sein, damit Änderungen möglich sind. Konfiguration wird beim Start geladen; nach ACL-Änderungen oder Tokenwiderruf den Dienst neu starten. Alle Replikate müssen die Änderung übernehmen. Nur **eine Instanz** mit diesem lokalen SQLite-Volume betreiben.

## 3. Image

Das Image wird von Portainer beim Deployen des Git-Stacks direkt auf dem Docker-Host aus dem `Dockerfile` dieses Repositorys gebaut (`build:` und `pull_policy: build` in `docker-compose.yml`). Eine Registry ist nicht nötig. Für einen manuellen Build:

```bash
docker build -t m365-cloud-mcp:local .
```

Das Image enthält Python 3.12, PowerShell 7.4 und ExchangeOnlineManagement 3.9.0. Python-Abhängigkeiten sind in `requirements.lock` festgelegt; Basisimages erhalten Sicherheitsupdates über ihre Tags. Für vollständig fixierte Releases die geprüften Basisimage-Digests festhalten. Auf ARM-Hosts zuerst die Verfügbarkeit der Basisimages und des EXO-Moduls prüfen; gegebenenfalls auf einem amd64-Host bauen und betreiben.

Der Docker-Host braucht beim Build Zugriff auf `mcr.microsoft.com`, Docker Hub, die PowerShell Gallery und PyPI.

## 4. Dateien auf dem Docker-Host bereitstellen

Beispielpfade:

```text
/srv/m365-mcp/config/tenants.json
/srv/m365-mcp/secrets/m365.pfx
/srv/m365-mcp/secrets/pfx_password
```

Der Container läuft als UID/GID `10001`. Verzeichnisse müssen für diese Identität durchquerbar und die Dateien lesbar sein. Beispielsweise Eigentümer `root:10001`, Verzeichnisse `0750`, Dateien `0440`. Keine Geheimnisse als Stack-Umgebungsvariablen eintragen. Die Pfade müssen auf dem Docker-/Agent-Host liegen, nicht nur auf dem Portainer-Server.

Das benannte Volume `m365_data` enthält Pläne und das Audit-Log. Für Backups SQLite-kompatible Backups oder einen gestoppten Dienst verwenden; keinen ungeschützten Live-Dateikopie-Workflow einrichten. Audit enthält Kunden- und Zielobjekt-IDs. Zugriffsrechte und Aufbewahrung entsprechend festlegen. Der Dienst rotiert Auditdaten noch nicht automatisch.

## 5. Portainer-Stack starten

In Portainer **Stacks → Add stack → Repository** wählen. Für Docker Standalone ausgelegt, nicht für Swarm.

- Repository URL: `https://github.com/KDT-Solutions/o365-mcp`
- Repository reference: Branch, aus dem deployt werden soll, z.B. `refs/heads/main`
- Compose path: `docker-compose.yml`
- Authentication: bei privatem Repository aktivieren, GitHub-Benutzer und ein Personal Access Token mit Lesezugriff auf das Repository hinterlegen
- Optional **GitOps updates** aktivieren (Polling oder Webhook), damit Portainer neue Commits automatisch baut und deployt

Folgende Stack-Variablen unter **Environment variables** setzen:

```text
MCP_HOST=mcp.deine-domain.de
MCP_PORT=8085
MCP_CONFIG_DIR=/srv/m365-mcp/config
MCP_SECRET_DIR=/srv/m365-mcp/secrets
```

`MCP_IMAGE` ist optional und legt nur den lokalen Tag des gebauten Images fest (Standard `m365-cloud-mcp:local`). Nach einem Update im Repository den Stack mit **Pull and redeploy** neu deployen; dabei wird das Image neu gebaut.

Der MCP-Port wird ausschließlich an `127.0.0.1` des Docker-Hosts gebunden. Ein vorhandener HTTPS-Reverse-Proxy auf diesem Host leitet an `http://127.0.0.1:8085` weiter. `Caddyfile.example` zeigt diese Variante; Caddy ist nicht Teil des Stacks. Bei einem Reverse-Proxy in einem anderen Container stattdessen ein gemeinsames internes Docker-Netz konfigurieren und an `m365-mcp:8000` weiterleiten. `127.0.0.1` innerhalb eines anderen Containers zeigt nicht auf den Host.

Öffentliches Ziel: `https://mcp.deine-domain.de/mcp`. Der Proxy muss den ursprünglichen Host-Header und den Authorization-Header weiterleiten, Streaming unterstützen und HTTPS erzwingen. Bei URLs mit explizitem Port `ALLOWED_HOSTS` entsprechend anpassen. Keine Request-Header mit Bearer-Tokens im Proxy protokollieren.

`/healthz` prüft, ob der HTTP-Dienst läuft; es führt keinen Microsoft-Login aus und bestätigt keine Graph-/Exchange-Berechtigungen.

## 6. MCP-Client verbinden

Für Clients mit Streamable HTTP und eigenen Authorization-Headern:

```json
{
  "mcpServers": {
    "m365": {
      "type": "http",
      "url": "https://mcp.deine-domain.de/mcp",
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
