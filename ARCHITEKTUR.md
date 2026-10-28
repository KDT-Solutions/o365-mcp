# Microsoft-365 Cloud MCP – Architekturentwurf

Status: Ursprünglicher Architekturentwurf. Die erste Implementierung verwendet App-Zugriff mit Zertifikat und einen Docker-Standalone-Stack für Portainer. Aktueller Funktionsumfang und Einschränkungen stehen in README.md; noch keine Verbindung zu echten Kundentenants.

## Ziel

Ein per HTTPS erreichbarer MCP-Dienst verwaltet explizit freigegebene Microsoft-365-Kundentenants. Kundenauswahl und Berechtigungen werden serverseitig geprüft. Admin-Passwörter werden nicht gespeichert.

## Gewählte Umsetzung und noch offene Einrichtung

1. Gewählt: Anwendungszugriff nach dem Modell der beigefügten Screenshots.
2. Implementiert: Graph-Inventar, Exchange-Postfachabfragen, Pläne für Kontosperrung und Postfachkonvertierung.
3. Gewählt: Portainer. Noch einzurichten: Hostname, Entra-App, Zertifikat und Kundenzustimmung. Bearer-fähiger MCP-Client erforderlich; eine OAuth-Schicht für andere Clients ist noch nicht enthalten.

## Zwei unterschiedliche Identitätsmodelle

### Delegierter Zugriff

Microsoft OAuth Authorization Code Flow mit PKCE und tenantgebundener Anmeldung. Der Administrator meldet sich beim jeweiligen Kundentenant an. MFA, Conditional Access, erforderliche Rollen und erneute Anmeldung bleiben wirksam. Tokens werden verschlüsselt und getrennt nach Tenant und Benutzer gespeichert. Änderungen an Rollen, widerrufene Sitzungen und Interaktionsanforderungen müssen als erneute Anmeldung behandelt werden.

Effektive Rechte ergeben sich aus delegierten Scopes und den Rechten des angemeldeten Administrators. Die serverseitige Zuordnung zum MCP-Benutzer muss zusätzlich geprüft werden. Exchange-Unterstützung muss separat auf den konkreten Anmeldeweg geprüft werden.

### Anwendungszugriff mit Zertifikat

Eine mandantenfähige Entra-App im eigenen Tenant wird durch einen berechtigten Administrator jedes Kunden freigegeben. Danach handelt der Service Principal der Anwendung im Kundentenant. Die Zustimmung durch einen individuellen Admin macht spätere Aktionen nicht zu Aktionen dieses Admin-Kontos.

Tokenbeschaffung erfolgt tenantgebunden über Client Credentials mit Zertifikat. Access-Tokens laufen ab und werden automatisch erneuert. Zertifikate benötigen Ablaufüberwachung und Rotation. Entzug von Zustimmung oder Berechtigungen muss den Zugriff zuverlässig beenden.

## Gemeinsamer Aufbau

- MCP über Streamable HTTP hinter einem HTTPS-Reverse-Proxy.
- Eigene Authentifizierung des MCP-Clients; sie ist unabhängig vom Microsoft-Login. Für den Zielclient kompatibles OAuth mit Ressourcen-/Audience-Prüfung und serverseitiger Autorisierung vorsehen. Microsoft-Graph-Tokens sind keine MCP-Zugangstokens.
- Explizite Kundenregistrierung mit Alias, unveränderlicher Tenant-ID und freigegebenen Bedienern. Kein frei wählbarer Authority-Host und keine beliebigen Graph-URLs als Toolparameter.
- Jede Toolausführung prüft Bediener, Tenant und erlaubte Aktion; kein globaler impliziter „aktueller Kunde“.
- Für Graph nur definierte Endpunkte und Felder. Pagination, Zeitlimits, begrenzte Wiederholungen bei 429/temporären Fehlern und Retry-After berücksichtigen.
- Audit mit Bediener, Tenant, Aktion, Ziel, Zeitpunkt und Ergebnis. Tokens, private Schlüssel und sensible API-Antworten nicht protokollieren.
- Zertifikate bzw. verschlüsselte Token-Caches über Secret Store bereitstellen; keine Geheimnisse im Repository oder Containerimage.

## Vorschlag für die erste Ausbaustufe

Nur lesende Tools: zugängliche Kunden auflisten, Benutzer anzeigen, Gruppen anzeigen und abonnierte Lizenz-SKUs anzeigen. Microsoft-Berechtigungen anhand der tatsächlich gewählten Endpunkte bestimmen und dokumentieren. Keine pauschalen Schreibrechte.

Anschließend gezielte Schreibtools für bestätigte Anforderungen. Jede Änderung benennt Kundentenant und Zielobjekt eindeutig. Für mehrstufiges Offboarding zunächst einen überprüfbaren Plan erzeugen; Teilerfolge und Fehler einzeln ausweisen. Lizenzentzug, Kontosperrung und Postfachänderungen haben unterschiedliche Voraussetzungen und dürfen nicht als atomarer Vorgang dargestellt werden.

## Exchange Online

Postfachkonvertierung erfolgt über unterstützte Exchange-Online-PowerShell-Cmdlets; keine frei ausführbaren PowerShell-Befehle als MCP-Tool anbieten. Für App-Zugriff sind unter anderem Exchange.ManageAsApp und ein für die benötigten Cmdlets unterstütztes Rollenmodell zu prüfen. Eine breit berechtigte Exchange-Administrator-Rolle nicht ungeprüft als Standard verwenden. Linux-/PowerShell-/Modulversion und Zertifikatsformat müssen zusammen getestet werden.

## Bereitstellung und Abnahme

Docker/Portainer ist als Hostingoption geeignet. Persistenz und Secret-Mounts getrennt vom Image; öffentlich nur HTTPS, kein ungeschützter MCP-Port. Healthcheck, Neustartverhalten und Datensicherung vorsehen.

Vor Produktivbetrieb prüfen: nicht autorisierte Bediener, fremde Tenant-IDs, ungültige Token-Audience, widerrufene Microsoft-Berechtigungen, Tokenablauf, Graph-Fehler und tenantübergreifende Isolation. Integration zuerst mit einem ausgewählten Testtenant. Ohne App-Registrierung, Kundenzustimmung und Hostingkonfiguration ist keine produktive Verbindung möglich.
