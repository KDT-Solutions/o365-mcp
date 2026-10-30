# Gewünschter Gesamtumfang und tatsächlicher Stand

Gewählt: App mit Zertifikat, mehrere freigegebene Kundentenants, Portainer Docker Standalone.

| Bereich | Implementiert | Noch erforderlich |
|---|---|---|
| Tenantzugriff | Kundenregister (fest oder per `add_tenant` zur Laufzeit), Consent-Link, `verify_tenant`, Bediener-ACL, Bearer-Authentifizierung | Freigabe eines zur Laufzeit angelegten Kunden für weitere Bediener; OAuth ergänzen, wenn der MCP-Client es benötigt |
| Benutzer | Auflisten, Detailabfrage, Kontosperrung, Sitzungswiderruf, Passwort-Reset, MFA-Methoden lesen und zurücksetzen | Anlage, Profiländerungen, Wiederherstellung, Löschprozesse |
| Lizenzen | Inventar, direkte Zuweisung/Entfernung über bestätigten Plan | Einzelne Servicepläne, gruppenbasierte Zuweisung und Standardpakete |
| Gruppen | Inventar, Mitglieder lesen, statische Cloud-Mitgliedschaften ändern | Eigentümer, Gruppenanlage, dynamische und Exchange-verwaltete Gruppen |
| Exchange | Postfächer lesen und in Shared Mailbox konvertieren; Vollzugriff, Senden-als und Standardkalender-Berechtigungen lesen und ändern | Weiterleitung, Senden-im-Auftrag, weitere Kalenderordner, Verteiler, Archiv, Retention; Kalender von Microsoft-365-Gruppen |
| Sicherheit | Anmeldeprotokolle (interaktiv und nicht interaktiv) mit Zusammenfassung nach IP/Land/Fehlern, Entra-Überwachungsprotokoll, riskante Benutzer, Risikoverlauf, Risikoerkennungen, Posteingangsregeln mit Weiterleitungs-/Löschwarnung; Benutzerrisiko verwerfen oder Kompromittierung bestätigen über bestätigten Plan | Conditional-Access-Richtlinien lesen, Geräte, Defender-Warnungen, Weiterleitung per Exchange setzen |
| Teams | Teams-Mitgliedschaften eines Benutzers lesen; Microsoft-365-Gruppenmitgliedschaft ändern | Teams-/Kanalverwaltung und Richtlinien |
| Teams-Telefonie | Noch nicht implementiert | Calling Plan / Operator Connect / Direct Routing je Kunde klären; benötigte Cmdlets auf App-only-Unterstützung prüfen |
| Onboarding | Einzelne Lizenz-/Gruppenaktionen vorhanden | Kundenstandard für Benutzeranlage, Lizenzpakete, Gruppen, Postfach und Telefonie; Ausführung mit Teilergebnisprotokoll |
| Offboarding | Einzelne Kontosperrung, Sitzungswiderruf, Gruppen-/Lizenzänderung, Shared-Konvertierung | Freigegebener Ablauf für Datenaufbewahrung, Delegation, Weiterleitung, Telefonie und Löschfristen |

Alle implementierten Microsoft-Aktionen müssen noch gegen einen echten Testtenant geprüft werden. Lokale Tests verwenden simulierte Provider. Ein erfolgreich gebautes Containerimage bestätigt keine Microsoft-Berechtigungen oder Exchange-Cmdlet-Kompatibilität im Kundentenant.

## Anforderungen an weitere Module

Keine generische Ausführung beliebiger Graph-URLs oder PowerShell-Kommandos. Jede Aktion erhält feste Parameter, passende Kundenautorisierung, eine dokumentierte Microsoft-Berechtigung und einen überprüfbaren Änderungsplan. Mehrstufige Abläufe protokollieren Teilerfolge; Microsoft-365-Änderungen lassen sich nicht als eine gemeinsame Datenbanktransaktion ausführen.

Für Teams-Telefonie nicht automatisch dasselbe Zertifikat als ausreichende Berechtigung annehmen. Der MicrosoftTeams-PowerShell-Zugang benötigt eigene API-Berechtigungen und Rollen. Cmdlet-Unterstützung für Service Principals und den gewählten Telefonie-Anbieter zuerst anhand der aktuellen Microsoft-Dokumentation und im Testtenant prüfen. Wenn eine Funktion nur delegiert unterstützt wird, muss dieser Unterschied sichtbar bleiben.

„Alles aus der Admin-Konsole“ ist kein abgeschlossener API-Funktionskatalog. Die implementierten Tools oben sind der belastbare aktuelle Umfang; weitere Bereiche wie SharePoint, Geräte, Security/Compliance, Billing oder Partner Center sind nicht enthalten.
