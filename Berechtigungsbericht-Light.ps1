#Requires -Version 5.1
<#
.SYNOPSIS
    LIGHT-VERSION (4 von 14 Prüfpunkten, kostenlos). Berechtigungsbericht: zeigt, wer in welcher Gruppe ist (auch verschachtelt), wer delegierte Rechte auf
    Organisationseinheiten, das Domänenobjekt und Gruppenrichtlinien hat, und erzeugt einen HTML-Bericht
    mit Auffälligkeiten.

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Berechtigungen, Gruppen oder Objekte und
    überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien) in den
    angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" und ein Domänenkonto mit Leserechten.
    Administratorrechte sind nicht erforderlich.

    Ausgewertet werden die Berechtigungen im Active Directory selbst (wer darf Konten anlegen, Kennwörter
    zurücksetzen, Gruppen ändern, Richtlinien bearbeiten). Berechtigungen auf Dateifreigaben prüft das
    Skript nicht.

.PARAMETER Ausgabe
    Pfad der HTML-Datei. Standard: Berechtigungsbericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER MaxGruppen
    Konten, die (auch verschachtelt) in mehr Gruppen sind, werden gemeldet (Standard 60).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft.
    Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Schreibt zusätzlich die vollständige Liste aller Gruppenmitgliedschaften, alle delegierten Rechte und
    je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Berechtigungsbericht.ps1

.EXAMPLE
    .\Berechtigungsbericht.ps1 -Csv -Ausgabe C:\Berichte\berechtigungen.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [ValidateRange(2, 5000)][int]$MaxGruppen = 60,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
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
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
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
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
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
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, $Bezug, $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

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
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten lesen
Write-Host 'Berechtigungsbericht - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$wurzel = Get-ADRootDSE @ad
$stammSid = $sid
try { if ($wald.RootDomain -ne $dom.DNSRoot) { $stammSid = (Get-ADDomain -Identity $wald.RootDomain @ad).DomainSID.Value } } catch { }

Write-Host '  Schema (Namen der Rechte und Eigenschaften) ...'
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
    '00299570-246d-11d0-a768-00aa006e0529' = 'Kennwort zurücksetzen'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'Kennwort ändern'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Verzeichnisänderungen replizieren'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Alle Verzeichnisänderungen replizieren (DCSync)'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'Verzeichnisänderungen in gefilterter Menge replizieren'
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
$jedermann = @{ 'S-1-1-0' = 'Jeder'; 'S-1-5-11' = 'Authentifizierte Benutzer'; 'S-1-5-7' = 'Anonymous-Anmeldung'; 'S-1-5-32-545' = 'Benutzer'; "$sid-513" = 'Domänen-Benutzer'; "$sid-515" = 'Domänencomputer'; 'S-1-5-32-554' = 'Prä-Windows 2000 kompatibler Zugriff' }
$bekannt = @{ 'S-1-5-18' = 'SYSTEM'; 'S-1-5-10' = 'SELBST'; 'S-1-3-0' = 'ERSTELLER-BESITZER'; 'S-1-5-9' = 'Domänencontroller der Organisation'; 'S-1-5-4' = 'INTERAKTIV'; 'S-1-5-2' = 'NETZWERK' }
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
            return , @('Anlegen/Löschen: ' + (GuidText $ot ''))
        }
        if ($ot -ne $leer) { return , @('Vollzugriff (Zusatz: ObjectType ' + (GuidText $ot '') + ')') }
        return , @('Vollzugriff')
    }
    $t = @()
    if ($r -band $R::WriteDacl) { $t += 'Berechtigungen ändern' }
    if ($r -band $R::WriteOwner) { $t += 'Besitz übernehmen' }
    if ($r -band $R::WriteProperty) { $t += 'Schreiben: ' + (GuidText $ot 'alle Eigenschaften') }
    if ($r -band $R::CreateChild) { $t += 'Anlegen: ' + (GuidText $ot 'alle Objekte') }
    if ($r -band $R::DeleteChild) { $t += 'Löschen: ' + (GuidText $ot 'alle Objekte') }
    if (($r -band $R::Delete) -or ($r -band $R::DeleteTree)) { $t += 'Dieses Objekt löschen' }
    if ($r -band $R::ExtendedRight) {
        if ($ot -eq $leer) { $t += 'Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)' }
        elseif ($ot -in $gefaehrlich) { $t += GuidText $ot '' }
    }
    if (($r -band $R::Self) -and -not ($r -band $R::WriteProperty)) { $t += 'Bestätigtes Schreiben: ' + (GuidText $ot 'alle') }
    , $t
}
function GiltFuer($ace) {
    $io = "$($ace.InheritedObjectType)"
    $was = if ($io -eq $leer) { 'alle Objekte' } else { GuidText $io '' }
    switch ("$($ace.InheritanceType)") {
        'None' { 'nur dieses Objekt' }
        'All' { if ($io -eq $leer) { 'dieses Objekt und alles darunter' } else { "$was darunter" } }
        default { "$was darunter" }
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

Write-Host '  Berechtigungen auf Domäne, Organisationseinheiten und Gruppenrichtlinien ...'
$domObj = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor @ad
$ous = @(Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor @ad | Sort-Object { $_.DistinguishedName.Length }, DistinguishedName)
$container = @()
foreach ($c in "CN=Users,$dn", "CN=Computers,$dn") { try { $container += Get-ADObject -Identity $c -Properties nTSecurityDescriptor @ad } catch { } }
$gpos = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$dn" -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, nTSecurityDescriptor @ad)
$sdh = $null
try { $sdh = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$dn" -Properties nTSecurityDescriptor @ad } catch { }

function Pfad($o) { if ($o.DistinguishedName -eq $dn) { "Domäne $($dom.DNSRoot)" } else { ($o.DistinguishedName -replace ",$([regex]::Escape($dn))$", '') } }
$unlesbar = @()
foreach ($o in @($domObj) + $ous + $container + $gpos + @($sdh)) { if ($o -and -not $o.nTSecurityDescriptor) { $unlesbar += [pscustomobject]@{ Objekt = Pfad $o; Feststellung = 'Berechtigungen nicht lesbar - nicht geprüft' } } }

$eDom = @(Eintraege $domObj (Pfad $domObj))
$eOu = @(foreach ($o in $ous + $container) { Eintraege $o (Pfad $o) })
$eGpo = @(foreach ($g in $gpos) { Eintraege $g "Richtlinie $($g.displayName)" })
$eSdh = @(if ($sdh) { Eintraege $sdh 'AdminSDHolder' })
$alleE = $eDom + $eOu

# ------------------------------------------------------------------ Gruppen
Write-Host '  Gruppen und Mitgliedschaften ...'
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
Write-Host '  Auswertung ...'
Befund 'B1' 'Domäne' 'Replikationsrechte (DCSync) außerhalb der Standardkonten' 'Hoch' `
($eDom | Where-Object { -not $_.Vertraut -and -not (ExchangeUeblich $_) -and $_.AmObjekt -and ("$($_.Roh.ObjectType)" -eq $dcsync -or $_.Rechte -match '^Vollzugriff|Alle erweiterten Rechte') } | ForEach-Object { Zeile $_ }) `
    'Wer am Domänenobjekt "Alle Verzeichnisänderungen replizieren" darf, kann die Kennwort-Hashwerte aller Konten abrufen - auch die der Administratoren (DCSync). Im Auslieferungszustand haben das nur Domänencontroller und Administratoren. Das Synchronisationskonto von Microsoft Entra Connect (MSOL_...) braucht dieses Recht und erscheint hier zu Recht.' `
    'Jeden Eintrag prüfen. Unbekannte Einträge sofort entfernen und als Sicherheitsvorfall behandeln; das Konto von Entra Connect wie ein Administratorkonto schützen.'

Befund 'B4' 'Delegierung' 'Schreibrechte für Jeder, Authentifizierte Benutzer oder Domänen-Benutzer' 'Hoch' `
(($alleE + $eGpo + $eSdh) | Where-Object { $_.Jedermann -and $_.Rechte -notmatch '^Bestätigtes Schreiben' } | ForEach-Object { Zeile $_ }) `
    'Diese Rechte gelten praktisch für jedes Konto der Domäne. Jeder Mitarbeiter und jedes übernommene Benutzerkonto kann die genannten Objekte verändern.' `
    'Eintrag entfernen und das Recht gezielt an eine eigene Gruppe vergeben.'

Befund 'B7' 'Delegierung' 'Rechte für gelöschte Konten (verwaiste SIDs)' 'Niedrig' `
(($alleE + $eGpo + $eSdh) | Where-Object { $_.Art -eq 'Verwaist' } | ForEach-Object { Zeile $_ }) `
    'Das Konto, dem dieses Recht gehörte, gibt es nicht mehr. Der Eintrag ist wirkungslos, macht die Berechtigungen aber unübersichtlich. SIDs aus vertrauten fremden Domänen können hier ebenfalls erscheinen, wenn sie sich nicht auflösen lassen.' `
    'Einträge entfernen.'

Befund 'B11' 'Gruppen' 'Gruppen, die sich im Kreis enthalten' 'Niedrig' `
($kreise | ForEach-Object { [pscustomobject]@{ Kreis = $_ } }) `
    'Gruppe A ist Mitglied von B und B wieder von A. Technisch funktioniert das, macht Mitgliedschaften aber unübersichtlich und bringt manche Anwendungen in Endlosschleifen.' `
    'Eine der Mitgliedschaften entfernen.'

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
    'Domäne (NetBIOS)'                 = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Gruppen (mit Mitgliedern / gesamt)' = "$(@($gruppenListe).Count) / $($gruppen.Count)"
    'Ausgewertete Mitgliedschaften'    = $mitgliedschaften.Count
    'Geprüfte Objekte'                 = "Domänenobjekt, $($ous.Count) Organisationseinheiten, $($container.Count) Standardcontainer, $($gpos.Count) Gruppenrichtlinien, AdminSDHolder"
    'Delegierte Rechte (ohne Standard)' = $deleg.Count
    'Schwellen dieses Berichts'        = "Konten in mehr als $MaxGruppen Gruppen"
    'Hinweis'                          = 'Mitglieder über die primäre Gruppe (z. B. Domänen-Benutzer) sind nicht einzeln aufgeführt.'
}
$basis = BerichtSchreiben -Name 'Berechtigungsbericht Light' -Datei 'Berechtigungsbericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ 'Mitglieder der privilegierten Gruppen (auch verschachtelt)' = $privListe; 'Gruppen im Überblick' = $gruppenListe }) `
    -Fuss 'Light-Version mit 4 von 14 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/xyjmdr). Ausgewertet wurden Gruppenmitgliedschaften und Berechtigungen im Active Directory, nicht die Berechtigungen auf Dateifreigaben. Der Bericht zeigt Auffälligkeiten anhand fester Regeln; er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit. Er enthält Konto- und Gruppennamen - bitte vertraulich behandeln.'
if ($Csv) {
    $mitgliedschaften | Export-Csv -Path "${basis}_Gruppenmitglieder.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    ($alleE + $eGpo + $eSdh) | ForEach-Object { $z = Zeile $_; $z | Add-Member -NotePropertyName Standard -NotePropertyValue (JaNein ($_.Vertraut -or $_.Jedermann)) -PassThru } |
        Export-Csv -Path "${basis}_Rechte.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
