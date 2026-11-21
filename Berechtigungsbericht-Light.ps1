<#
.SYNOPSIS
    LIGHT VERSION (4 of 14 checks, free). Permission report: shows who is in which group (including nested), who has delegated rights on
    organizational units, the domain object, and Group Policies, and generates an HTML report
    with anomalies.

    Deutsch:
    LIGHT-VERSION (4 von 14 Prüfpunkten, kostenlos). Berechtigungsbericht: zeigt, wer in welcher Gruppe ist (auch verschachtelt), wer delegierte Rechte auf
    Organisationseinheiten, das Domänenobjekt und Gruppenrichtlinien hat, und erzeugt einen HTML-Bericht
    mit Auffälligkeiten.

.DESCRIPTION
    The script operates exclusively in READ-ONLY mode. It does not change permissions, groups, or objects and
    sends no data to third parties or the internet. It writes exactly one HTML file (and, if requested, CSV files) to the
    specified output folder.

    Prerequisites: Windows PowerShell 5.1, the "ActiveDirectory" module, and a domain account with read permissions.
    Administrator rights are not required.

    The permissions in Active Directory itself are evaluated (who may create accounts, reset passwords, change groups, edit policies). The script does not check permissions on file shares.

    Deutsch:
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Berechtigungen, Gruppen oder Objekte und
    sendet keine Daten an Dritte oder ins Internet. Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien) in den
    angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" und ein Domänenkonto mit Leserechten.
    Administratorrechte sind nicht erforderlich.

    Ausgewertet werden die Berechtigungen im Active Directory selbst (wer darf Konten anlegen, Kennwörter
    zurücksetzen, Gruppen ändern, Richtlinien bearbeiten). Berechtigungen auf Dateifreigaben prüft das
    Skript nicht.

.PARAMETER Ausgabe
    Path of the HTML file. Default: Berechtigungsbericht_<Domäne>_<Datum>.html in the current folder.

    Deutsch:
    Pfad der HTML-Datei. Standard: Berechtigungsbericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER MaxGruppen
    Accounts that are members of more groups (including nested) are reported (default 60).

    Deutsch:
    Konten, die (auch verschachtelt) in mehr Gruppen sind, werden gemeldet (Standard 60).

.PARAMETER Server
    Specific domain controller or domain (optional).

    Deutsch:
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Credentials for a domain account (Get-Credential) if the script is not running as a domain user.
    Then also specify -Server.

    Deutsch:
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft.
    Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Additionally writes the complete list of all group memberships, all delegated rights, and
    a CSV file for each checkpoint with hits alongside the report.

    Deutsch:
    Schreibt zusätzlich die vollständige Liste aller Gruppenmitgliedschaften, alle delegierten Rechte und
    je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Does not automatically open the finished report in the browser.

    Deutsch:
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Additionally returns the findings as objects (for custom evaluations).

    Deutsch:
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.PARAMETER Language
    Language of the report and the console output: 'de' (German) or 'en' (English). Default: German if the Windows display language
    is German, otherwise English.

    Deutsch:
    Sprache von Bericht und Konsolenausgabe: 'de' (Deutsch) oder 'en' (Englisch). Standard: Deutsch, wenn die Anzeigesprache von
    Windows Deutsch ist, sonst Englisch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Berechtigungsbericht.ps1

.EXAMPLE
    .\Berechtigungsbericht.ps1 -Csv -Ausgabe C:\Berichte\berechtigungen.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' }),
    [Alias('Output')][string]$Ausgabe,
    [ValidateRange(2, 5000)][int]$MaxGruppen = 60,
    [string]$Server,
    [Alias('Credential')][System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [Alias('NoOpen')][switch]$NichtOeffnen,
    [switch]$PassThru
)
# Sprache des Berichts: de oder en (Parameter -Language). T 'deutsch' 'english' liefert den Text der gewählten Sprache.
$En = ($Language -eq 'en')
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

$ErrorActionPreference = 'Stop'
$Version = '1.1'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host (T 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.' 'Windows 10/11: Settings > Optional features > Add "RSAT: Active Directory Domain Services".')
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

#@SPRACHE@
# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        if ($alle.Count) { $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }   # leere Liste: keine Datei (sie hätte keine Kopfzeile)
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -ge 2) {
        $namen = New-Object System.Collections.Generic.List[string]
        foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
        if ($namen.Count -ne @($liste[0].PSObject.Properties.Name).Count) { $liste = @($liste | Select-Object -Property $namen) }
    }
    SpaltenAnzeige $liste
}
# Englische Berichte: Spaltenüberschriften aus der Übersetzungstabelle (intern bleiben die deutschen Namen, der Code liest sie weiter)
$SpaltenEn = @{
    'Abfrage' = 'Query'
    'Administrator' = 'Administrator'
    'Adresse' = 'Address'
    'Aktiv' = 'Active'
    'Aktiv verknüpft mit' = 'Active linked to'
    'Aktive Verknüpfungen' = 'Active links'
    'Alter in Tagen' = 'Age in days'
    'Angelegt' = 'Created'
    'Anmeldung' = 'Last logon'
    'Anmeldungen' = 'Logons'
    'Anteil (%)' = 'Share (%)'
    'Anzahl' = 'Count'
    'Art' = 'Account type'
    'Auf Domänencontroller' = 'On domain controller'
    'Aufräumen' = 'Cleanup'
    'Auslastung' = 'Utilization'
    'Auslösender Rechner' = 'Triggering computer'
    'Auslösender Rechner (Anzahl)' = 'Triggering computers (count)'
    'Aussteller' = 'Issuer'
    'Beispiele' = 'Examples'
    'Belegt' = 'Used'
    'Belegt (%)' = 'Used (%)'
    'Benutzer und Computer (auch verschachtelt)' = 'Users and computers (also nested)'
    'Benutzereinstellungen' = 'User settings'
    'Benutzername' = 'Username'
    'Berechtigter' = 'Principal'
    'Bereich' = 'Scope'
    'Bereiche' = 'Scopes'
    'Beschreibung' = 'Description'
    'Besitzer' = 'Owner'
    'Betriebssystem' = 'OS'
    'Betroffene Konten' = 'Affected accounts'
    'Bewertung' = 'Rating'
    'Bis' = 'To'
    'BitLocker' = 'BitLocker'
    'Computer' = 'Computer'
    'Computereinstellungen' = 'Computer settings'
    'Darf anwenden' = 'Can apply'
    'Darf delegieren an' = 'Can delegate to'
    'Darf sich hier als Benutzer ausgeben' = 'Can log on as user'
    'Datei' = 'File'
    'Dateien' = 'Files'
    'Dateisystem' = 'File system'
    'Dateityp' = 'File type'
    'Datenbank' = 'Database'
    'Detail' = 'Detail'
    'Details' = 'Details'
    'Direkte Mitglieder' = 'Direct members'
    'Domäne' = 'Domain'
    'Domänencontroller' = 'Domain controller'
    'Domänennamenmaster' = 'Domain naming master'
    'Dynamische Updates' = 'Dynamic updates'
    'E-Mail' = 'Email'
    'Eigenschaft' = 'Property'
    'Einstellung' = 'Setting'
    'Empfohlen' = 'Recommended'
    'Enthaltene Gruppen' = 'Included groups'
    'Ereignisse' = 'Events'
    'Erreichbar' = 'Reachable'
    'Erste' = 'First'
    'Erster' = 'First'
    'Erzwungen' = 'Forced'
    'Failover' = 'Failover'
    'Falsches Kennwort' = 'Wrong password'
    'Fehlanmeldungen am DC' = 'Failed logons at DC'
    'Fehlversuche' = 'Failed attempts'
    'Feststellung' = 'Finding'
    'Fingerabdruck' = 'Fingerprint'
    'Firewall' = 'Firewall'
    'Frei' = 'Free'
    'Freigabe' = 'Share'
    'Freigaberecht' = 'Share permission'
    'Funktion' = 'Function'
    'Gelesen von' = 'Read by'
    'Geprüft' = 'Checked'
    'Gesamtgröße' = 'Total size'
    'Geschützte Benutzer' = 'Protected users'
    'Gesperrt seit' = 'Locked since'
    'Geändert' = 'Changed'
    'Gilt' = 'Applies to'
    'Gilt für' = 'Applies to'
    'Globaler Katalog' = 'Global catalog'
    'Grenze' = 'Limit'
    'Groesse' = 'Size'
    'Grund' = 'Reason'
    'Gruppe' = 'Group'
    'Gruppen' = 'Groups'
    'Gruppen (auch verschachtelt)' = 'Groups (including nested)'
    'Gruppenrichtlinie' = 'Group policy'
    'Größe' = 'Size'
    'Größe (GB)' = 'Size (GB)'
    'Gültig ab' = 'Valid from'
    'Gültig bis' = 'Valid to'
    'Herkunft' = 'Origin'
    'Hersteller' = 'Vendor'
    'Hinweis' = 'Note'
    'Häufigster Grund' = 'Most common reason'
    'IP-Adresse' = 'IP address'
    'Im AD gespeichert' = 'Stored in AD'
    'In der Domäne vorhanden' = 'Present in domain'
    'Infrastrukturmaster' = 'Infrastructure master'
    'Inhalt' = 'Content'
    'Ist' = 'Is'
    'Kennung' = 'ID'
    'Kennwort gesetzt' = 'Password set'
    'Kennwort läuft nie ab' = 'Password never expires'
    'Kerberos' = 'Kerberos'
    'Konten' = 'Accounts'
    'Konten (auch verschachtelt)' = 'Accounts (also nested)'
    'Konto' = 'Account'
    'Konto für DNS-Einträge' = 'Account for DNS entries'
    'Kopie bleibt im Postfach' = 'Copy remains in mailbox'
    'LAPS' = 'LAPS'
    'LAPS-Ablauf' = 'LAPS expiry'
    'Laufwerk' = 'Drive'
    'Lease-Dauer' = 'Lease duration'
    'Leitet weiter an' = 'Forwards to'
    'Leseweg' = 'Read path'
    'Letzte Aktualisierung' = 'Last update'
    'Letzte Anmeldung' = 'Last logon'
    'Letzte Vollsicherung' = 'Last full backup'
    'Letzte inkrementelle Sicherung' = 'Last incremental backup'
    'Letzter' = 'Last'
    'Letzter Aufräumlauf' = 'Last cleanup run'
    'Letzter Start' = 'Last start'
    'Lokale Admins' = 'Local admins'
    'Mindestlänge' = 'Minimum length'
    'Mitglied' = 'Member'
    'Mitglieder' = 'Members'
    'NLA' = 'NLA'
    'NTLM' = 'NTLM'
    'Name' = 'Name'
    'Nr.' = 'No.'
    'Objekt' = 'Object'
    'Ordner' = 'Folder'
    'Organisationseinheit' = 'OU'
    'Ort' = 'Location'
    'PDC-Emulator' = 'PDC emulator'
    'Pfad' = 'Path'
    'Postfach' = 'Mailbox'
    'Postfach-Typ' = 'Mailbox type'
    'Postfachtyp' = 'Mailbox type'
    'Postfächer' = 'Mailboxes'
    'Privilegierte Gruppen' = 'Privileged groups'
    'Programm' = 'Program'
    'Prüfpunkt' = 'Checkpoint'
    'Quelle' = 'Source'
    'Quelle (Anzahl)' = 'Sources (count)'
    'RID-Master' = 'RID master'
    'Recht' = 'Permission'
    'Rechte' = 'Permissions'
    'Regel' = 'Rule'
    'Reihenfolge' = 'Order'
    'SPN' = 'SPN'
    'Schemamaster' = 'Schema master'
    'Schlüssel' = 'Key'
    'Schreibgeschützt' = 'Read-only'
    'Sendesperre ab' = 'Send blocked from'
    'Server' = 'Server'
    'Sid' = 'SID'
    'Signatur' = 'Signature'
    'Speicher' = 'Storage'
    'Sperrungen' = 'Lockouts'
    'Stand' = 'Status'
    'Standort' = 'Site'
    'Status' = 'Status'
    'Support-Ende' = 'End of support'
    'Support-Ende (spätestes)' = 'End of support (latest)'
    'Tage bis Ablauf' = 'Days until expiry'
    'Tage her' = 'Days ago'
    'Tage ohne Anmeldung' = 'Days without logon'
    'Tage seit Ablauf' = 'Days since expiry'
    'Treffer' = 'Hits'
    'Typ' = 'Type'
    'Vererbung' = 'Inheritance'
    'Verschiedene Konten' = 'Distinct accounts'
    'Verschlüsselt' = 'Encrypted'
    'Version' = 'Version'
    'Version C/B' = 'Version C/B'
    'Verweigert für' = 'Denied for'
    'Verwendung' = 'Use'
    'Virenschutz' = 'Antivirus'
    'Von' = 'From'
    'WMI-Filter' = 'WMI filter'
    'Weg' = 'Path'
    'Weiterleitungen' = 'Forwarding'
    'Wert' = 'Value'
    'Wirksame Richtlinie' = 'Effective policy'
    'Wirksames Recht' = 'Effective permission'
    'Wirkung' = 'Effect'
    'Zeit' = 'Time'
    'Zeitpunkt' = 'Time'
    'Zeitraum' = 'Period'
    'Zertifikat' = 'Certificate'
    'Zone' = 'Zone'
    'Zonen' = 'Zones'
    'Zonenübertragung' = 'Zone transfer'
    'Zugriff für große Gruppen' = 'Access for large groups'
    'Zugriffsbasierte Aufzählung' = 'Access-based enumeration'
    'Zuletzt' = 'Last'
    'Zustand' = 'State'
    'davon Größe (GB)' = 'Of which size (GB)'
    'davon aktiv' = 'Of which active'
    'davon inaktiv' = 'Of which inactive'
    'davon unbekannte Konten' = 'Of which unknown accounts'
    'ist Mitglied von' = 'Member of'
    'Älter als 5 Jahre' = 'Older than 5 years'
    'Älter als 5 Jahren' = 'Older than 5 years'
    'Ältester Eintrag' = 'Oldest entry'
    'Über' = 'Via'
    'Überwachungsprotokoll' = 'Audit log'
}
# Werte, die der Code intern auf Deutsch vergleicht (z. B. Art = 'Benutzer'), erscheinen im englischen Bericht übersetzt (nur Anzeige und CSV)
$WerteEn = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)   # Groß-/Kleinschreibung zählt (Verwaist / verwaist)
$WerteEn.Add('Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)', 'All extended rights (including password reset)')
$WerteEn.Add('Kein Serverbetriebssystem (Support nicht bewertet)', 'No server operating system (support not assessed)')
$WerteEn.Add('Rechte je Ordner (nur dort, wo sie gesetzt werden)', 'Permissions per folder (only where set)')
$WerteEn.Add('Mehrfach freigegebene Ordner (nur einmal gezählt)', 'Folders shared multiple times (counted only once)')
$WerteEn.Add('Übersprungene Verknüpfungen (Junctions/Symlinks)', 'Skipped links (Junctions/Symlinks)')
$WerteEn.Add('Der Ordner der Freigabe existiert nicht mehr.', 'The share folder no longer exists.')
$WerteEn.Add('DHCP-Überwachungsprotokoll ist ausgeschaltet', 'DHCP audit log is disabled')
$WerteEn.Add('Vollzugriff und "Senden als" im Überblick', 'Full access and "Send as" overview')
$WerteEn.Add('Ordner der Freigabe existiert nicht mehr', 'Share folder no longer exists')
$WerteEn.Add('Enthält außer Sicherheitseinstellungen:', 'Contains except security settings:')
$WerteEn.Add('Nicht geprüft - Postfach nicht gefunden', 'Not checked - mailbox not found')
$WerteEn.Add('WMI-Filter nicht lesbar - nicht geprüft', 'WMI filter not readable - not checked')
$WerteEn.Add('Abfrage fehlgeschlagen - nicht geprüft', 'Query failed - not checked')
$WerteEn.Add('Nicht im Active Directory gespeichert', 'Not stored in Active Directory')
$WerteEn.Add('keine im Active Directory autorisiert', 'None authorized in Active Directory')
$WerteEn.Add('Zugriff auf den Ordner nicht möglich', 'Access to folder not possible')
$WerteEn.Add('Zertifikate (öffentliche Schlüssel)', 'Certificates (public keys)')
$WerteEn.Add('Domänencontroller der Organisation', 'Organization domain controllers')
$WerteEn.Add('Remotedesktop erlaubt Verbindungen', 'Remote Desktop allows connections')
$WerteEn.Add('autorisierte DHCP-Server ermitteln', 'Determine authorized DHCP servers')
$WerteEn.Add('Windows Server 2008 R2 und älter', 'Windows Server 2008 R2 and older')
$WerteEn.Add('Konto deaktiviert oder gesperrt', 'Account disabled or locked')
$WerteEn.Add('Vollzugriff (Zusatz: ObjectType', 'Full access (additional: ObjectType')
$WerteEn.Add('Kennwort oder Konto abgelaufen', 'Password or account expired')
$WerteEn.Add('Lokale Administratorengruppen', 'Local administrator groups')
$WerteEn.Add('Berechtigungen/Besitz ändern', 'Change permissions/ownership')
$WerteEn.Add('Freigabepfade nicht sichtbar', 'Share paths not visible')
$WerteEn.Add('Aktive privilegierte Konten', 'Active privileged accounts')
$WerteEn.Add('Gruppe hat keine Mitglieder', 'Group has no members')
$WerteEn.Add('Keine Verbindung zum Server', 'No connection to server')
$WerteEn.Add('unerlaubte Zeichen im Namen', 'Illegal characters in name')
$WerteEn.Add('Geprüfte Domänencontroller', 'Checked domain controllers')
$WerteEn.Add('Authentifizierte Benutzer', 'Authenticated Users')
$WerteEn.Add('Schwellen dieses Berichts', 'Thresholds of this report')
$WerteEn.Add('Benutzer (inetOrgPerson)', 'User (inetOrgPerson)')
$WerteEn.Add('Datenbestand je Freigabe', 'Data inventory per share')
$WerteEn.Add('Kontosperrungsrichtlinie', 'Account lockout policy')
$WerteEn.Add('Sicherheitseinstellungen', 'Security settings')
$WerteEn.Add('Alle erweiterten Rechte', 'All extended rights')
$WerteEn.Add('Hinweise zur Auswertung', 'Notes for evaluation')
$WerteEn.Add('Nicht abgefragte Server', 'Servers not queried')
$WerteEn.Add('Unterordner und Dateien', 'Subfolders and files')
$WerteEn.Add('Bestätigtes Schreiben:', 'Validated write:')
$WerteEn.Add('Installierte Programme', 'Installed programs')
$WerteEn.Add('Konto für DNS-Einträge', 'Account for DNS records')
$WerteEn.Add('Kontosperrungsschwelle', 'Account lockout threshold')
$WerteEn.Add('Nicht lesbare Bereiche', 'Unreadable areas')
$WerteEn.Add('Berechtigungen ändern', 'Change permissions')
$WerteEn.Add('Hinweise zum Auslesen', 'Notes for reading')
$WerteEn.Add('Windows 8.1 und älter', 'Windows 8.1 and older')
$WerteEn.Add('Überwachungsprotokoll', 'Audit log')
$WerteEn.Add('Nicht berücksichtigt', 'Not considered')
$WerteEn.Add('Anonymous-Anmeldung', 'Anonymous logon')
$WerteEn.Add('Infrastrukturmaster', 'Infrastructure master')
$WerteEn.Add('Secure Boot ist aus', 'Secure Boot is off')
$WerteEn.Add('Domänennamenmaster', 'Domain naming master')
$WerteEn.Add('Kennwortrichtlinie', 'Password policy')
$WerteEn.Add('Komponentenwartung', 'Component servicing')
$WerteEn.Add('alle Eigenschaften', 'all properties')
$WerteEn.Add('Besitz übernehmen', 'Take ownership')
$WerteEn.Add('Domänencontroller', 'Domain Controllers')
$WerteEn.Add('Falsches Kennwort', 'Incorrect password')
$WerteEn.Add('Konten-Operatoren', 'Account Operators')
$WerteEn.Add('Nur dieser Ordner', 'Only this folder')
$WerteEn.Add('Domänen-Benutzer', 'Domain Users')
$WerteEn.Add('Format unbekannt', 'Format unknown')
$WerteEn.Add('Sonstige Dateien', 'Other files')
$WerteEn.Add('Ältester Eintrag', 'Oldest entry')
$WerteEn.Add('Domänencomputer', 'Domain Computers')
$WerteEn.Add('Konto unbekannt', 'Account unknown')
$WerteEn.Add('Standard (alle)', 'Default (all)')
$WerteEn.Add('Computerkonten', 'Computer accounts')
$WerteEn.Add('Konto gesperrt', 'Account locked')
$WerteEn.Add('Nicht erreicht', 'Not reached')
$WerteEn.Add('DHCP-Bereiche', 'DHCP scopes')
$WerteEn.Add('Dieser Ordner', 'This folder')
$WerteEn.Add('Gruppe/System', 'Group/system')
$WerteEn.Add('Remotedesktop', 'Remote Desktop')
$WerteEn.Add('Arbeitsplatz', 'Workstation')
$WerteEn.Add('Schemamaster', 'Schema master')
$WerteEn.Add('DHCP-Server', 'DHCP server')
$WerteEn.Add('Datenbanken', 'Databases')
$WerteEn.Add('Sonderkonto', 'Special account')
$WerteEn.Add('Unterordner', 'Subfolders')
$WerteEn.Add('Vollzugriff', 'Full control')
$WerteEn.Add('Zugriff von', 'Access from')
$WerteEn.Add('DNS-Server', 'DNS server')
$WerteEn.Add('Inaktiv ab', 'Inactive from')
$WerteEn.Add('Schreiben:', 'Write:')
$WerteEn.Add('Verweigern', 'Deny')
$WerteEn.Add('DNS-Zonen', 'DNS zones')
$WerteEn.Add('Schreiben', 'Write')
$WerteEn.Add('Sonstiges', 'Other')
$WerteEn.Add('Standorte', 'Sites')
$WerteEn.Add('Unbekannt', 'Unknown')
$WerteEn.Add('unbekannt', 'unknown')
$WerteEn.Add('(Wurzel)', '(root)')
$WerteEn.Add('Anlegen:', 'Create:')
$WerteEn.Add('Benutzer', 'User')
$WerteEn.Add('Erlauben', 'Allow')
$WerteEn.Add('Netzwerk', 'Network')
$WerteEn.Add('Verwaist', 'Orphaned')
$WerteEn.Add('verwaist', 'orphaned')
$WerteEn.Add('Dateien', 'Files')
$WerteEn.Add('Gruppen', 'Groups')
$WerteEn.Add('Anonym', 'Anonymous')
$WerteEn.Add('Domäne', 'Domain')
$WerteEn.Add('Gruppe', 'Group')
$WerteEn.Add('Umfang', 'Scope')
$WerteEn.Add('direkt', 'direct')
$WerteEn.Add('Ändern', 'Change')
$WerteEn.Add('Lesen', 'Read')
$WerteEn.Add('über', 'via')
$WerteMuster = @()
foreach ($k in ($WerteEn.Keys | Sort-Object Length -Descending)) { $WerteMuster += , @([regex]::new('(?<![\p{L}\d])' + [regex]::Escape($k) + '(?![\p{L}\d])'), $WerteEn[$k]) }
function WertAnzeige($v) {
    if (-not $script:En -or $v -isnot [string] -or -not $v) { return $v }
    if ($v.Contains('\')) { return $v }   # Kontonamen (DOMÄNE\Name) und Pfade bleiben, wie sie sind
    foreach ($m in $WerteMuster) { $v = $m[0].Replace($v, $m[1]) }
    $v
}
function SpaltenAnzeige($liste) {
    if (-not $script:En -or -not @($liste).Count) { return $liste }
    foreach ($o in @($liste)) {
        $n = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $k = $p.Name; if ($SpaltenEn.ContainsKey($k)) { $k = $SpaltenEn[$k] }; $i = 2; $k0 = $k; while ($n.Contains($k)) { $k = "$k0 $i"; $i++ }; $n[$k] = WertAnzeige $p.Value }
        [pscustomobject]$n
    }
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
# Deutsch und Englisch: Skripte erzeugen den Text je nach -Language, erkannt werden beide Fassungen
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft',
    'Query failed - not checked', 'Permissions not readable - not checked', 'SYSVOL not readable - not checked', 'WMI filter not readable - not checked', 'No domain controller found - SYSVOL not checked', 'Folder content not readable - policy not checked')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *') -or ("$($o.Feststellung)" -clike 'Not checked - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = $(T 'Abfrage nicht möglich' 'query not possible')) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = (T "Nicht geprüft - $Grund (siehe $Verweis)" "Not checked - $Grund (see $Verweis)"); Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = $(T 'Domäne' 'Domain'), [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html "$env:USERDOMAIN\$env:USERNAME") $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); Info = (T 'Hinweise und nicht geprüft' 'notes and not checked'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html (WertAnzeige $k))</td><td>$(Html (WertAnzeige $Umgebung[$k]))</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html (WertAnzeige $k))</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>$(T 'Keine Einträge.' 'No entries.')</p>") }
    }

    [void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>$(T 'Keine Auffälligkeiten gefunden.' 'No anomalies found.')</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert.' 'The script only read and changed nothing.') $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host ((T 'Bericht' 'Report') + ": $ziel")
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten lesen
Write-Host (T 'Berechtigungsbericht - es wird nur gelesen, nichts verändert.' 'Permission report - only read, nothing changed.') -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$wurzel = Get-ADRootDSE @ad
$stammSid = $sid
try { if ($wald.RootDomain -ne $dom.DNSRoot) { $stammSid = (Get-ADDomain -Identity $wald.RootDomain @ad).DomainSID.Value } } catch { }

Write-Host (T '  Schema (Namen der Rechte und Eigenschaften) ...' 'Schema (names of rights and properties) ...')
$guidName = @{}
Get-ADObject -SearchBase $wurzel.schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties lDAPDisplayName, schemaIDGUID @ad |
    ForEach-Object { $guidName[([guid]$_.schemaIDGUID).Guid] = $_.lDAPDisplayName }
# Klassen des Schemas: ein GenericAll-Eintrag, dessen ObjectType eine Klasse ist, gewährt nur das Anlegen und Löschen von Objekten dieser Klasse
# (im Test mit Testkonten belegt: weder Berechtigungen ändern noch Besitz übernehmen noch DCSync)
$klassenGuid = @{}
Get-ADObject -SearchBase $wurzel.schemaNamingContext -LDAPFilter '(objectClass=classSchema)' -Properties schemaIDGUID @ad |
    ForEach-Object { $klassenGuid[([guid]$_.schemaIDGUID).Guid] = 1 }
Get-ADObject -SearchBase "CN=Extended-Rights,$($wurzel.configurationNamingContext)" -LDAPFilter '(rightsGuid=*)' -Properties displayName, rightsGuid @ad |
    ForEach-Object { $guidName[([guid]$_.rightsGuid).Guid] = $_.displayName }
# Deutsche Namen für die wichtigsten Rechte und Klassen
$deutsch = @{
    '00299570-246d-11d0-a768-00aa006e0529' = (T 'Kennwort zurücksetzen' 'Reset password')
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = (T 'Kennwort ändern' 'Change password')
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = (T 'Verzeichnisänderungen replizieren' 'Replicate Directory Changes')
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = (T 'Alle Verzeichnisänderungen replizieren (DCSync)' 'Replicate all directory changes (DCSync)')
    '89e95b76-444d-4c62-991a-0facbeda640c' = (T 'Verzeichnisänderungen in gefilterter Menge replizieren' 'Replicate Directory Changes in Filtered Set')
}
foreach ($k in $deutsch.Keys) { $guidName[$k] = $deutsch[$k] }
$klasse = @{ user = 'Benutzer'; group = 'Gruppen'; computer = 'Computer'; organizationalUnit = 'Organisationseinheiten'; contact = 'Kontakte'; inetOrgPerson = 'Benutzer (inetOrgPerson)'; groupPolicyContainer = 'Gruppenrichtlinien' }
$leer = [guid]::Empty.Guid
$gefaehrlich = '00299570-246d-11d0-a768-00aa006e0529', '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'
$dcsync = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

# Konten, deren Rechte zum Auslieferungszustand gehören bzw. die ohnehin Administratoren sind
$vertraut = @('S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-550', 'S-1-5-32-560', 'S-1-5-32-561',
    "$sid-512", "$sid-516", "$sid-517", "$sid-521", "$sid-526", "$stammSid-519", "$stammSid-498", "$stammSid-527", "$stammSid-518")
# Sammelgruppen, in denen (fast) jeder Mitglied ist
$jedermann = @{ 'S-1-1-0' = 'Jeder'; 'S-1-5-11' = 'Authentifizierte Benutzer'; 'S-1-5-7' = (T 'Anonymous-Anmeldung' 'Anonymous logon'); 'S-1-5-32-545' = 'Benutzer'; "$sid-513" = 'Domänen-Benutzer'; "$sid-515" = 'Domänencomputer'; 'S-1-5-32-554' = (T 'Prä-Windows 2000 kompatibler Zugriff' 'Pre-Windows 2000 compatible access') }
$bekannt = @{ 'S-1-5-18' = 'SYSTEM'; 'S-1-5-10' = 'SELBST'; 'S-1-3-0' = (T 'ERSTELLER-BESITZER' 'CREATOR-OWNER'); 'S-1-5-9' = (T 'Domänencontroller der Organisation' 'Organization domain controllers'); 'S-1-5-4' = 'INTERAKTIV'; 'S-1-5-2' = 'NETZWERK' }
foreach ($k in $jedermann.Keys) { $bekannt[$k] = $jedermann[$k] }

$sidCache = @{}
function Wer($s) {
    # Liefert Name, Art (Benutzer/Gruppe/Computer/Sonderkonto/Verwaist) zu einer SID
    $s = "$s"
    if (-not $sidCache.ContainsKey($s)) {
        $e = $null
        try { $o = Get-ADObject -LDAPFilter "(objectSid=$s)" -Properties sAMAccountName, objectClass @ad } catch { $o = $null }
        if ($o) {
            # Verwaltete Dienstkonten (gMSA) tragen auch "computer" in der Klassenliste: zuerst prüfen, sonst erscheinen sie als Computer
            $k = "$($o.objectClass)"
            $art = if ($k -match 'msDS-.*ServiceAccount') { 'Benutzer' } elseif ($k -match 'computer') { 'Computer' } elseif ($k -match 'group') { 'Gruppe' } elseif ($k -match 'user') { 'Benutzer' } else { 'Sonderkonto' }
            $e = [pscustomobject]@{ Name = $(if ($o.sAMAccountName) { $o.sAMAccountName } else { $o.Name }); Art = $art }
            if ($bekannt.ContainsKey($s)) { $e.Name = $bekannt[$s] }
        } elseif ($bekannt.ContainsKey($s)) { $e = [pscustomobject]@{ Name = $bekannt[$s]; Art = 'Sonderkonto' } }
        elseif ($s -like 'S-1-5-21-*') { $e = [pscustomobject]@{ Name = $s; Art = 'Verwaist' } }
        else { $e = [pscustomobject]@{ Name = $s; Art = 'Sonderkonto' } }
        $sidCache[$s] = $e
    }
    $sidCache[$s]
}
function GuidText($g, $sonst) { $g = "$g"; if ($g -eq $leer) { $sonst } elseif ($guidName.ContainsKey($g)) { $n = $guidName[$g]; if ($klasse.ContainsKey($n)) { $klasse[$n] } else { $n } } else { $g } }

$R = [System.DirectoryServices.ActiveDirectoryRights]
function RechteText($ace) {
    # Übersetzt einen Zugriffseintrag in lesbare Rechte; leere Liste = nur Leserechte
    $r = $ace.ActiveDirectoryRights
    $ot = "$($ace.ObjectType)"
    if (($r -band $R::GenericAll) -eq $R::GenericAll) {
        # GenericAll mit einer Objektklasse als ObjectType gewährt am Objekt selbst nur das Anlegen und Löschen von Objekten dieser Klasse (im Test mit
        # Testkonten belegt) - aber nur, wenn der Eintrag nicht weitervererbt wird und die Klasse nicht zum Objekt selbst gehört (eigene Klasse oder
        # Oberklasse): sonst gilt der Eintrag für das Objekt bzw. die darunter liegenden Objekte vollständig. Im Zweifel bleibt es Vollzugriff.
        if ($ot -ne $leer -and $klassenGuid.ContainsKey($ot) -and "$($ace.InheritanceType)" -eq 'None' -and -not $script:eigeneKlassen.ContainsKey($ot)) {
            return , @((T 'Anlegen/Löschen: ' 'Create/delete:') + (GuidText $ot ''))
        }
        if ($ot -ne $leer) { return , @('Vollzugriff (Zusatz: ObjectType ' + (GuidText $ot '') + ')') }
        return , @('Vollzugriff')
    }
    $t = @()
    if ($r -band $R::WriteDacl) { $t += 'Berechtigungen ändern' }
    if ($r -band $R::WriteOwner) { $t += 'Besitz übernehmen' }
    if ($r -band $R::WriteProperty) { $t += 'Schreiben: ' + (GuidText $ot 'alle Eigenschaften') }
    if ($r -band $R::CreateChild) { $t += 'Anlegen: ' + (GuidText $ot (T 'alle Objekte' 'all objects')) }
    if ($r -band $R::DeleteChild) { $t += (T 'Löschen: ' 'Delete:') + (GuidText $ot (T 'alle Objekte' 'all objects')) }
    if (($r -band $R::Delete) -or ($r -band $R::DeleteTree)) { $t += (T 'Dieses Objekt löschen' 'Delete this object') }
    if ($r -band $R::ExtendedRight) {
        if ($ot -eq $leer) { $t += 'Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)' }
        elseif ($ot -in $gefaehrlich) { $t += GuidText $ot '' }
    }
    if (($r -band $R::Self) -and -not ($r -band $R::WriteProperty)) {
        # Self-Membership (bf9679c0-...) erlaubt, sich selbst in die Gruppe einzutragen: nie als harmloses bestätigtes Schreiben behandeln
        if ($ot -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') { $t += (T 'Selbst als Mitglied eintragen (Self-Membership)' 'Add yourself as a member (Self-Membership)') } elseif ($ot -eq $leer) { $t += (T 'Alle bestätigten Schreibrechte (auch Selbst als Mitglied eintragen)' 'All confirmed write permissions (also add Self as member)') } else { $t += 'Bestätigtes Schreiben: ' + (GuidText $ot (T 'alle' 'all')) }
    }
    , $t
}
function GiltFuer($ace) {
    $io = "$($ace.InheritedObjectType)"
    $was = if ($io -eq $leer) { (T 'alle Objekte' 'all objects') } else { GuidText $io '' }
    switch ("$($ace.InheritanceType)") {
        'None' { (T 'nur dieses Objekt' 'only this object') }
        'All' { if ($io -eq $leer) { (T 'dieses Objekt und alles darunter' 'this object and everything below it') } else { (T "$was darunter" "$was below") } }
        default { (T "$was darunter" "$was below") }
    }
}

# Die von Exchange selbst angelegten, bekannten Gruppen (nur diese Namen, und nur in der OU "Microsoft Exchange Security Groups"): ihre Rechte am
# Domänenobjekt gehören zum Standard einer Exchange-Domäne. Sie werden getrennt unter B14 ausgewiesen, nicht als Angriffsspur unter B1 bis B3.
$exchangeSids = @{}
$exchangeBekannt = 'Exchange Trusted Subsystem', 'Exchange Windows Permissions', 'Organization Management', 'Exchange Servers', 'Exchange Enterprise Servers', 'Managed Availability Servers'
try {
    foreach ($n in $exchangeBekannt) {
        $g = Get-ADGroup -Filter "Name -eq '$n'" -SearchBase "OU=Microsoft Exchange Security Groups,$dn" -SearchScope OneLevel @ad -ErrorAction SilentlyContinue
        if ($g) { $exchangeSids[$g.SID.Value] = $g.SamAccountName }
    }
} catch { }

# Übliche Exchange-Einträge (Ausnahme für B1 bis B3): Eintrag einer bekannten Exchange-Gruppe, der keines der gefährlichen Rechte betrifft
# (Replikation/DCSync, Kennwort zurücksetzen). Replikationsrechte und Kennwort-Zurücksetzen einer Exchange-Gruppe werden immer gemeldet.
# Ein Eintrag OHNE ObjectType, der am Objekt selbst wirkt und Vollzugriff, alle erweiterten Rechte, Berechtigungen ändern oder Besitz übernehmen
# umfasst auch DCSync und Kennwort zurücksetzen: ebenfalls kein üblicher Eintrag. Nur nach unten vererbte Einträge (z. B. WriteDacl auf Benutzer)
# gehören zu Exchange und stehen unter B14.
function ExchangeUeblich($e) {
    if (-not $e.Exchange) { return $false }
    $ot = "$($e.Roh.ObjectType)"
    if ($ot -in $gefaehrlich) { return $false }
    if ($e.AmObjekt -and $ot -eq $leer -and $e.Rechte -match 'Vollzugriff|Alle erweiterten Rechte|Berechtigungen ändern|Besitz übernehmen') { return $false }
    $true
}
# Klassen, für die ein nach unten vererbter Eintrag praktisch alle Konten der Domäne betrifft (user, computer, group, organizationalUnit, inetOrgPerson)
$breiteKlassen = $leer, 'bf967aba-0de6-11d0-a285-00aa003049e2', 'bf967a86-0de6-11d0-a285-00aa003049e2', 'bf967a9c-0de6-11d0-a285-00aa003049e2', 'bf967aa5-0de6-11d0-a285-00aa003049e2', '4828cc14-1437-45bc-9b07-ad6f015e5f28'
function BreitVererbt($e) { (-not $e.AmObjekt) -and ("$($e.Roh.InheritedObjectType)" -in $breiteKlassen) }

# Liest die Zugriffseinträge eines Objekts; liefert je schreibendem Eintrag eine Zeile
function Eintraege($obj, $bezeichnung, [switch]$AuchGeerbt) {
    $sd = $obj.nTSecurityDescriptor
    if (-not $sd) { return }
    # Klassen des Objekts selbst (eigene Klasse und Oberklassen); unbekannt = alle Klassen gelten als eigene (vorsichtig)
    $script:eigeneKlassen = @{}
    $oc = @($obj.objectClass) + 'top'
    if ("$($obj.objectClass)" -eq 'domainDNS') { $oc += 'domain' }
    foreach ($gid in $klassenGuid.Keys) { if ($guidName[$gid] -in $oc) { $script:eigeneKlassen[$gid] = 1 } }
    if (-not $obj.objectClass) { foreach ($gid in $klassenGuid.Keys) { $script:eigeneKlassen[$gid] = 1 } }
    foreach ($ace in $sd.GetAccessRules($true, [bool]$AuchGeerbt, [System.Security.Principal.SecurityIdentifier])) {
        if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
        $rechte = RechteText $ace
        if (-not $rechte.Count) { continue }
        $s = $ace.IdentityReference.Value
        $w = Wer $s
        [pscustomobject]@{
            Objekt = $bezeichnung; Sid = $s; Konto = $w.Name; Art = $w.Art; Rechte = ($rechte -join '; '); Gilt = GiltFuer $ace
            Vertraut = ($s -in $vertraut); Jedermann = $jedermann.ContainsKey($s); Roh = $ace
            AmObjekt = (-not ("$($ace.PropagationFlags)" -match 'InheritOnly'))
            Exchange = $exchangeSids.ContainsKey($s)
        }
    }
}
function Zeile($e) { [pscustomobject][ordered]@{ Objekt = $e.Objekt; Konto = $e.Konto; Art = $e.Art; Rechte = $e.Rechte; 'Gilt für' = $e.Gilt } }

Write-Host (T '  Berechtigungen auf Domäne, Organisationseinheiten und Gruppenrichtlinien ...' 'Permissions on domain, organizational units, and group policies ...')
$domObj = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor @ad
$ous = @(Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor @ad | Sort-Object { $_.DistinguishedName.Length }, DistinguishedName)
$container = @()
foreach ($c in "CN=Users,$dn", "CN=Computers,$dn") { try { $container += Get-ADObject -Identity $c -Properties nTSecurityDescriptor @ad } catch { } }
$gpos = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$dn" -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, nTSecurityDescriptor @ad)
$sdh = $null
try { $sdh = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$dn" -Properties nTSecurityDescriptor @ad } catch { }

function Pfad($o) { if ($o.DistinguishedName -eq $dn) { (T "Domäne $($dom.DNSRoot)" "Domain $($dom.DNSRoot)") } else { ($o.DistinguishedName -replace ",$([regex]::Escape($dn))$", '') } }
$unlesbar = @()
foreach ($o in @($domObj) + $ous + $container + $gpos + @($sdh)) { if ($o -and -not $o.nTSecurityDescriptor) { $unlesbar += [pscustomobject]@{ Objekt = Pfad $o; Feststellung = (T 'Berechtigungen nicht lesbar - nicht geprüft' 'Permissions not readable - not checked') } } }

$eDom = @(Eintraege $domObj (Pfad $domObj))
$eOu = @(foreach ($o in $ous + $container) { Eintraege $o (Pfad $o) })
$eGpo = @(foreach ($g in $gpos) { Eintraege $g (T "Richtlinie $($g.displayName)" "Policy $($g.displayName)") })
$eSdh = @(if ($sdh) { Eintraege $sdh 'AdminSDHolder' })
$alleE = $eDom + $eOu

# ------------------------------------------------------------------ Gruppen
Write-Host (T '  Gruppen und Mitgliedschaften ...' 'Groups and memberships ...')
$gruppen = @(Get-ADGroup -Filter * -Properties member, GroupScope, GroupCategory @ad)
$objekt = @{}   # DN -> Kurzinfo
foreach ($g in $gruppen) { $objekt[$g.DistinguishedName] = [pscustomobject]@{ Name = $g.SamAccountName; Art = 'Gruppe' } }
Get-ADUser -Filter * @ad | ForEach-Object { $objekt[$_.DistinguishedName] = [pscustomobject]@{ Name = $_.SamAccountName; Art = 'Benutzer' } }
Get-ADComputer -Filter * @ad | ForEach-Object { $objekt[$_.DistinguishedName] = [pscustomobject]@{ Name = $_.SamAccountName; Art = 'Computer' } }
$direkt = @{}
foreach ($g in $gruppen) { $direkt[$g.DistinguishedName] = @($g.member) }

# Effektive Mitglieder je Gruppe: DN des Mitglieds -> Weg ("direkt" oder "über Gruppe A > Gruppe B")
$effektiv = @{}
$kreise = New-Object System.Collections.Generic.List[string]
function Aufloesen($gdn, [string[]]$weg) {
    if ($effektiv.ContainsKey($gdn)) { return $effektiv[$gdn] }
    $erg = @{}
    foreach ($m in $direkt[$gdn]) { $erg[$m] = 'direkt' }
    foreach ($m in $direkt[$gdn]) {
        if ($direkt.ContainsKey($m)) {
            if ($m -eq $gdn -or $weg -contains $m) {
                $kreis = (@($weg + $gdn + $m) | ForEach-Object { $objekt[$_].Name }) -join ' > '
                if (-not $kreise.Contains($kreis)) { $kreise.Add($kreis) }
                continue
            }
            $unter = Aufloesen $m ($weg + $gdn)
            foreach ($u in $unter.Keys) {
                if ($u -ne $gdn -and -not $erg.ContainsKey($u)) { $erg[$u] = 'über ' + $objekt[$m].Name + $(if ($unter[$u] -ne 'direkt') { ' > ' + ($unter[$u] -replace '^über ') }) }
            }
        }
    }
    # Nur vollständig aufgelöste Gruppen merken (innerhalb eines Kreises wäre das Ergebnis unvollständig)
    if (-not $weg.Count) { $effektiv[$gdn] = $erg }
    $erg
}
foreach ($g in $gruppen) { [void](Aufloesen $g.DistinguishedName @()) }

$mitgliedschaften = foreach ($g in ($gruppen | Sort-Object SamAccountName)) {
    $e = $effektiv[$g.DistinguishedName]
    foreach ($m in $e.Keys) {
        $o = $objekt[$m]
        [pscustomobject][ordered]@{
            Gruppe = $g.SamAccountName; Mitglied = $(if ($o) { $o.Name } else { ($m -split ',')[0] -replace '^CN=' })
            Art = $(if ($o) { $o.Art } else { 'Sonstiges' }); Weg = $e[$m]
        }
    }
}
$mitgliedschaften = @($mitgliedschaften)
$jeKonto = @{}
foreach ($m in ($mitgliedschaften | Where-Object { $_.Art -ne 'Gruppe' })) { $jeKonto[$m.Mitglied] = 1 + [int]$jeKonto[$m.Mitglied] }

$privSids = [ordered]@{ "$sid-512" = 1; "$stammSid-519" = 1; "$stammSid-518" = 1; 'S-1-5-32-544' = 1; 'S-1-5-32-548' = 1; 'S-1-5-32-549' = 1; 'S-1-5-32-551' = 1; 'S-1-5-32-550' = 1; "$sid-520" = 1 }
$privNamen = @($gruppen | Where-Object { $privSids.Contains($_.SID.Value) } | ForEach-Object { $_.SamAccountName })
$privListe = @($mitgliedschaften | Where-Object { $_.Gruppe -in $privNamen -and $_.Art -ne 'Gruppe' } | Sort-Object Gruppe, Mitglied)
# Konten, die über die privilegierten Gruppen ohnehin Administratoren sind (auch verschachtelt)
$adminKonten = @{}
foreach ($m in $privListe) { $adminKonten[$m.Mitglied] = 1 }

# ------------------------------------------------------------------ Prüfungen
Write-Host (T '  Auswertung ...' '  Evaluation ...')
Befund 'B1' (T 'Domäne' 'Domain') (T 'Replikationsrechte (DCSync) außerhalb der Standardkonten' 'Replication permissions (DCSync) outside standard accounts') 'Hoch' `
($eDom | Where-Object { -not $_.Vertraut -and -not (ExchangeUeblich $_) -and $_.AmObjekt -and ("$($_.Roh.ObjectType)" -eq $dcsync -or $_.Rechte -match '^Vollzugriff|Alle erweiterten Rechte') } | ForEach-Object { Zeile $_ }) `
    (T 'Wer am Domänenobjekt "Alle Verzeichnisänderungen replizieren" darf, kann die Kennwort-Hashwerte aller Konten abrufen - auch die der Administratoren (DCSync). Im Auslieferungszustand haben das nur Domänencontroller und Administratoren. Das Synchronisationskonto von Microsoft Entra Connect (MSOL_...) braucht dieses Recht und erscheint hier zu Recht.' 'Anyone who can "Replicate Directory Changes All" on the domain object can retrieve password hash values for all accounts—including those of administrators (DCSync). By default, only domain controllers and administrators have this. The Microsoft Entra Connect synchronization account (MSOL_...) requires this permission and appears here legitimately.') `
    (T 'Jeden Eintrag prüfen. Unbekannte Einträge sofort entfernen und als Sicherheitsvorfall behandeln; das Konto von Entra Connect wie ein Administratorkonto schützen.' 'Check every entry. Remove unknown entries immediately and treat them as a security incident; protect the Entra Connect account like an administrator account.')

Befund 'B4' (T 'Delegierung' 'Delegation') (T 'Schreibrechte für Jeder, Authentifizierte Benutzer oder Domänen-Benutzer' 'Write permissions for Everyone, Authenticated Users, or Domain Users') 'Hoch' `
(($alleE + $eGpo + $eSdh) | Where-Object { $_.Jedermann -and $_.Rechte -notmatch '^Bestätigtes Schreiben' } | ForEach-Object { Zeile $_ }) `
    (T 'Diese Rechte gelten praktisch für jedes Konto der Domäne. Jeder Mitarbeiter und jedes übernommene Benutzerkonto kann die genannten Objekte verändern.' 'These rights effectively apply to every account in the domain. Every employee and every compromised user account can modify the mentioned objects.') `
    (T 'Eintrag entfernen und das Recht gezielt an eine eigene Gruppe vergeben.' 'Remove the entry and assign the permission specifically to a dedicated group.')

$deleg = @($alleE | Where-Object { -not $_.Vertraut -and -not $_.Jedermann -and $_.Art -ne 'Verwaist' })

Befund 'B7' (T 'Delegierung' 'Delegation') (T 'Rechte für gelöschte Konten (verwaiste SIDs)' 'Permissions for deleted accounts (orphaned SIDs)') 'Niedrig' `
(($alleE + $eGpo + $eSdh) | Where-Object { $_.Art -eq 'Verwaist' } | ForEach-Object { Zeile $_ }) `
    (T 'Das Konto, dem dieses Recht gehörte, gibt es nicht mehr. Der Eintrag ist wirkungslos, macht die Berechtigungen aber unübersichtlich. SIDs aus vertrauten fremden Domänen können hier ebenfalls erscheinen, wenn sie sich nicht auflösen lassen.' 'The account to which this right belonged no longer exists. The entry has no effect but makes the permissions unclear. SIDs from trusted external domains may also appear here if they cannot be resolved.') `
    (T 'Einträge entfernen.' 'Remove entries.')

Befund 'B11' (T 'Gruppen' 'Groups') (T 'Gruppen, die sich im Kreis enthalten' 'Groups that contain each other in a cycle') 'Niedrig' `
($kreise | ForEach-Object { [pscustomobject]@{ Kreis = $_ } }) `
    (T 'Gruppe A ist Mitglied von B und B wieder von A. Technisch funktioniert das, macht Mitgliedschaften aber unübersichtlich und bringt manche Anwendungen in Endlosschleifen.' 'Group A is a member of B, and B is again a member of A. Technically this works, but it makes memberships unclear and can put some applications into infinite loops.') `
    (T 'Eine der Mitgliedschaften entfernen.' 'Remove one of the memberships.')

# ------------------------------------------------------------------ Bericht
$gruppenListe = $gruppen | Where-Object { $effektiv[$_.DistinguishedName].Count } | Sort-Object SamAccountName | ForEach-Object {
    $e = $effektiv[$_.DistinguishedName]
    [pscustomobject][ordered]@{
        Gruppe = $_.SamAccountName; Bereich = "$($_.GroupScope)"; 'Direkte Mitglieder' = @($direkt[$_.DistinguishedName]).Count
        'Benutzer und Computer (auch verschachtelt)' = @($e.Keys | Where-Object { -not $direkt.ContainsKey($_) }).Count
        'Enthaltene Gruppen' = @($e.Keys | Where-Object { $direkt.ContainsKey($_) }).Count; Ort = Ort $_.DistinguishedName
    }
}
$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)')                 = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Gruppen (mit Mitgliedern / gesamt)' 'Groups (with members / total)') = "$(@($gruppenListe).Count) / $($gruppen.Count)"
    (T 'Ausgewertete Mitgliedschaften' 'Evaluated memberships')    = $mitgliedschaften.Count
    (T 'Geprüfte Objekte' 'Checked objects')                 = (T "Domänenobjekt, $($ous.Count) Organisationseinheiten, $($container.Count) Standardcontainer, $($gpos.Count) Gruppenrichtlinien, AdminSDHolder" "Domain object, $($ous.Count) organizational units, $($container.Count) default containers, $($gpos.Count) Group Policy Objects, AdminSDHolder")
    (T 'Delegierte Rechte (ohne Standard)' 'Delegated rights (excluding standard)') = $deleg.Count
    (T 'Schwellen dieses Berichts' 'Thresholds for this report')        = (T "Konten in mehr als $MaxGruppen Gruppen" "Accounts in more than $MaxGruppen groups")
    (T 'Hinweis' 'Note')               = (T 'Mitglieder über die primäre Gruppe (z. B. Domänen-Benutzer) sind nicht einzeln aufgeführt.' 'Members via the primary group (e.g., Domain Users) are not listed individually.')
}
$basis = BerichtSchreiben -Name (T 'Berechtigungsbericht Light' 'Permission report Light') -Datei 'Berechtigungsbericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ (T 'Mitglieder der privilegierten Gruppen (auch verschachtelt)' 'Members of privileged groups (including nested)') = $privListe; (T 'Gruppen im Überblick' 'Group overview') = $gruppenListe }) `
    -Fuss (T 'Light-Version mit 4 von 14 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/xyjmdr). Ausgewertet wurden Gruppenmitgliedschaften und Berechtigungen im Active Directory, nicht die Berechtigungen auf Dateifreigaben. Der Bericht zeigt Auffälligkeiten anhand fester Regeln; er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit. Er enthält Konto- und Gruppennamen - bitte vertraulich behandeln.' 'Light version with 4 of 14 checks of the full version (https://mueller86.gumroad.com/l/xyjmdr). Group memberships and permissions in Active Directory were evaluated, not permissions on file shares. The report shows findings based on fixed rules; it does not replace a security review and makes no claim to completeness. It contains account and group names - please treat as confidential.')
if ($Csv) {
    SpaltenAnzeige $mitgliedschaften | Export-Csv -Path "${basis}_Gruppenmitglieder.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    SpaltenAnzeige @(($alleE + $eGpo + $eSdh) | ForEach-Object { $z = Zeile $_; $z | Add-Member -NotePropertyName Standard -NotePropertyValue (JaNein ($_.Vertraut -or $_.Jedermann)) -PassThru }) |
        Export-Csv -Path "${basis}_Rechte.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
