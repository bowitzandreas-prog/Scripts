<#PSScriptInfo

.VERSION 0.2

.GUID 4279b966-262d-4b19-8f41-7c97b2d9d781

.AUTHOR Andreas Bowitz

.COPYRIGHT (c) 2026 Andreas Bowitz. Alle Rechte vorbehalten.

.TAGS WordPress Security wp2shell CVE-2026-63030 CVE-2026-60137 Hardening

.LICENSEURI

.PROJECTURI https://abow.info

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
0.2 (2026-Sep-28) Vollstaendige Hilfe, Script-Metadaten, Banner, Bewertungsstufen,
                  Exitcodes, -PassThru, -TimeoutSec, Autoren-Aufzaehlung, X-Powered-By.
0.1 (2026-Sep-28) Erste Version fuer den Beitrag auf abow.info.

.PRIVATEDATA

#>

<#
.SYNOPSIS
    Prueft von aussen, ob eine eigene WordPress-Seite fuer wp2shell
    (CVE-2026-63030 / CVE-2026-60137) angreifbar ist und welche weiteren
    Angriffsflaechen fuer Gaeste offen sind.

.DESCRIPTION
    Test-WpExposure schickt ausschliesslich harmlose Lese- bzw. Leeranfragen an
    eine WordPress-Seite und bewertet die Antworten. Auf dem Server wird nichts
    veraendert, es werden keine Exploits ausgefuehrt.

    Geprueft wird:
      1. Erreichbarkeit der Seite
      2. Oeffentlich sichtbare WordPress-Version (Meta-Generator, RSS-Feed) und
         Abgleich mit den von wp2shell betroffenen Versionen
         (6.9.0-6.9.4 und 7.0.0-7.0.1, Fix in 6.9.5 bzw. 7.0.2)
      3. REST-Batch-Endpunkt fuer Gaeste, ueber beide Routen
         (/wp-json/batch/v1 und /?rest_route=/batch/v1)
      4. XML-RPC (Angriffsflaeche fuer Passwort-Rateversuche)
      5. Benutzer-Aufzaehlung ueber die REST-API und ueber /?author=1
      6. PHP-Versionsangabe im Header X-Powered-By

    Bewertungsstufen: OK, Hinweis, Warnung, Kritisch.

    Nur gegen eigene Seiten oder mit ausdruecklicher Erlaubnis des Betreibers
    einsetzen.

.PARAMETER Url
    Basis-URL der WordPress-Seite inklusive https://, z. B. https://example.com

.PARAMETER TimeoutSec
    Zeitlimit pro Anfrage in Sekunden. Standard: 20.

.PARAMETER PassThru
    Gibt die Ergebnisse zusaetzlich als Objekte zurueck, z. B. fuer Export-Csv
    oder eigene Auswertungen.

.EXAMPLE
    .\Test-WpExposure.ps1 -Url https://example.com

    Prueft die Seite und zeigt eine farbige Uebersicht mit Zusammenfassung.

.EXAMPLE
    .\Test-WpExposure.ps1 -Url https://example.com -PassThru |
        Export-Csv -Path .\wp-check.csv -NoTypeInformation -Encoding UTF8

    Schreibt die Ergebnisse zusaetzlich in eine CSV-Datei.

.EXAMPLE
    .\Test-WpExposure.ps1 -Url https://example.com
    if ($LASTEXITCODE -eq 1) { Write-Warning 'Handlungsbedarf' }

    Nutzt den Exitcode, etwa in einer geplanten Aufgabe.

.INPUTS
    Keine. Die URL wird als Parameter uebergeben.

.OUTPUTS
    Mit -PassThru: PSCustomObject mit den Eigenschaften
    Pruefung, Ergebnis, Stufe und Bewertung.

.NOTES
    Name:        Test-WpExposure
    Author:      Andreas Bowitz
    Version:     0.2
    LastUpdated: 2026-Sep-28

    Voraussetzungen: Windows PowerShell 5.1 oder PowerShell 7.x
    Exitcodes:       0 = keine Warnung, 1 = Warnung oder Kritisch gefunden,
                     2 = Seite nicht erreichbar

    Downloadete Skripte ggf. vorher freigeben: Unblock-File .\Test-WpExposure.ps1

.LINK
    https://abow.info

.LINK
    https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = 'Basis-URL der WordPress-Seite, z. B. https://example.com')]
    [ValidatePattern('^https?://[^\s/$.?#].[^\s]*$')]
    [string]$Url,

    [ValidateRange(3, 120)]
    [int]$TimeoutSec = 20,

    [switch]$PassThru
)

#region Grundeinstellungen
$ScriptName    = 'Test-WpExposure'
$ScriptVersion = '0.2'
$ScriptAuthor  = 'Andreas Bowitz'
$UserAgent     = "$ScriptName/$ScriptVersion (+https://abow.info)"

if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
$Url     = $Url.TrimEnd('/')
$results = New-Object System.Collections.Generic.List[object]
#endregion

#region Hilfsfunktionen
function Get-HttpResult {
    <#
    .SYNOPSIS
        Fuehrt eine HTTP-Anfrage aus und liefert Status, Inhalt, Header und End-URL,
        auch bei Fehlerstatus. Kompatibel mit PowerShell 5.1 und 7.x.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType = 'application/json'
    )
    $p = @{
        Uri             = $Uri
        Method          = $Method
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
        TimeoutSec      = $TimeoutSec
        UserAgent       = $UserAgent
    }
    if ($Body) { $p.Body = $Body; $p.ContentType = $ContentType }

    try {
        $r       = Invoke-WebRequest @p
        $content = $r.Content
        if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
        $final = $null
        if ($r.BaseResponse.ResponseUri)    { $final = $r.BaseResponse.ResponseUri.AbsoluteUri }             # PS 5.1
        elseif ($r.BaseResponse.RequestMessage) { $final = $r.BaseResponse.RequestMessage.RequestUri.AbsoluteUri } # PS 7
        [pscustomobject]@{ Status = [int]$r.StatusCode; Content = [string]$content; Headers = $r.Headers; FinalUri = $final }
    }
    catch {
        $resp = $_.Exception.Response
        if ($resp) {
            [pscustomobject]@{ Status = [int]$resp.StatusCode; Content = ''; Headers = $null; FinalUri = $null }
        }
        else {
            [pscustomobject]@{ Status = -1; Content = $_.Exception.Message; Headers = $null; FinalUri = $null }
        }
    }
}

function Add-Result {
    param(
        [string]$Pruefung,
        [string]$Ergebnis,
        [ValidateSet('OK', 'Hinweis', 'Warnung', 'Kritisch')][string]$Stufe,
        [string]$Bewertung
    )
    $results.Add([pscustomobject]@{
        Pruefung  = $Pruefung
        Ergebnis  = $Ergebnis
        Stufe     = $Stufe
        Bewertung = $Bewertung
    })
}

function Test-Wp2shellVersion {
    param([string]$Version)
    $parts = @($Version.Split('.'))
    while ($parts.Count -lt 3) { $parts += '0' }
    $v = [version]($parts[0..2] -join '.')
    return (($v -ge [version]'6.9.0' -and $v -le [version]'6.9.4') -or
            ($v -ge [version]'7.0.0' -and $v -le [version]'7.0.1'))
}
#endregion

#region Banner
Write-Host ''
Write-Host "  $ScriptName v$ScriptVersion  |  $ScriptAuthor  |  abow.info" -ForegroundColor Cyan
Write-Host "  Ziel: $Url" -ForegroundColor Gray
Write-Host "  Nur gegen eigene Seiten einsetzen. Es werden keine Daten veraendert." -ForegroundColor DarkGray
Write-Host ''
#endregion

#region 1) Erreichbarkeit
$start = Get-HttpResult -Uri "$Url/"
if ($start.Status -lt 0) {
    Write-Host "  Seite nicht erreichbar: $($start.Content)" -ForegroundColor Red
    exit 2
}
Add-Result 'Erreichbarkeit' $start.Status 'OK' 'Seite antwortet'
#endregion

#region 2) WordPress-Version
$version = $null
$quelle  = $null
if ($start.Content -match '<meta[^>]+name=["'']generator["''][^>]+content=["'']WordPress\s+([0-9.]+)') {
    $version = $Matches[1]; $quelle = 'Meta-Generator'
}
if (-not $version) {
    foreach ($feedPath in '/feed/', '/?feed=rss2') {
        $feed = Get-HttpResult -Uri "$Url$feedPath"
        if ($feed.Content -match 'wordpress\.org/\?v=([0-9.]+)') { $version = $Matches[1]; $quelle = "Feed $feedPath"; break }
    }
}
if ($version) {
    if (Test-Wp2shellVersion $version) {
        Add-Result 'WordPress-Version' "$version ($quelle)" 'Kritisch' 'wp2shell-verwundbar: sofort updaten und auf Einbruch pruefen'
    }
    else {
        Add-Result 'WordPress-Version' "$version ($quelle)" 'Hinweis' 'nicht im betroffenen Bereich, Version aber oeffentlich sichtbar'
    }
}
else {
    Add-Result 'WordPress-Version' '-' 'OK' 'nicht oeffentlich sichtbar, bitte im Backend pruefen'
}
#endregion

#region 3) Batch-API (beide Routen)
foreach ($route in '/wp-json/batch/v1', '/?rest_route=/batch/v1') {
    $r = Get-HttpResult -Uri "$Url$route" -Method POST -Body '{"requests":[]}'
    if ($r.Status -in 401, 403) {
        Add-Result "Batch-API $route" $r.Status 'OK' 'fuer Gaeste gesperrt'
    }
    elseif ($r.Status -eq 404) {
        Add-Result "Batch-API $route" $r.Status 'OK' 'nicht vorhanden'
    }
    elseif ($r.Status -lt 0) {
        Add-Result "Batch-API $route" 'keine Antwort' 'Hinweis' 'Anfrage lief ins Leere, ggf. Firewall'
    }
    else {
        Add-Result "Batch-API $route" $r.Status 'Warnung' 'fuer Gaeste erreichbar, nur mit gepatchtem Core vertretbar'
    }
}
#endregion

#region 4) XML-RPC
$xml = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
$r   = Get-HttpResult -Uri "$Url/xmlrpc.php" -Method POST -Body $xml -ContentType 'text/xml'
if ($r.Status -eq 200 -and $r.Content -match '<string>') {
    Add-Result 'XML-RPC' $r.Status 'Warnung' 'offen, Ziel fuer Passwort-Rateversuche'
}
else {
    Add-Result 'XML-RPC' $r.Status 'OK' 'gesperrt oder ohne Methoden'
}
#endregion

#region 5) Benutzer-Aufzaehlung
foreach ($route in '/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users') {
    $r = Get-HttpResult -Uri "$Url$route"
    if ($r.Status -eq 200 -and $r.Content -match '"slug"\s*:\s*"([^"]+)"') {
        Add-Result "Benutzerliste $route" $r.Status 'Warnung' "Benutzernamen oeffentlich, z. B. '$($Matches[1])'"
    }
    else {
        Add-Result "Benutzerliste $route" $r.Status 'OK' 'nicht auslesbar'
    }
}
$r = Get-HttpResult -Uri "$Url/?author=1"
if ($r.FinalUri -match '/author/([^/?#]+)') {
    Add-Result 'Autoren-Weiterleitung /?author=1' $r.Status 'Hinweis' "verraet Benutzernamen '$($Matches[1])'"
}
else {
    Add-Result 'Autoren-Weiterleitung /?author=1' $r.Status 'OK' 'kein Benutzername erkennbar'
}
#endregion

#region 6) PHP-Version im Header
$powered = $null
if ($start.Headers) { $powered = $start.Headers['X-Powered-By'] }
if ($powered) {
    Add-Result 'Header X-Powered-By' ([string]$powered) 'Hinweis' 'PHP-Version sichtbar, expose_php = Off setzen'
}
else {
    Add-Result 'Header X-Powered-By' '-' 'OK' 'keine PHP-Version sichtbar'
}
#endregion

#region Ausgabe
$farbe = @{ OK = 'Green'; Hinweis = 'Cyan'; Warnung = 'Yellow'; Kritisch = 'Red' }
$w1 = ($results | ForEach-Object { $_.Pruefung.Length } | Measure-Object -Maximum).Maximum
$w2 = ($results | ForEach-Object { ([string]$_.Ergebnis).Length } | Measure-Object -Maximum).Maximum

foreach ($e in $results) {
    Write-Host ('  {0,-10}' -f "[$($e.Stufe)]") -ForegroundColor $farbe[$e.Stufe] -NoNewline
    Write-Host (" {0}  {1}  " -f $e.Pruefung.PadRight($w1), ([string]$e.Ergebnis).PadRight($w2)) -NoNewline
    Write-Host $e.Bewertung -ForegroundColor Gray
}

$kritisch = @($results | Where-Object Stufe -eq 'Kritisch').Count
$warnung  = @($results | Where-Object Stufe -eq 'Warnung').Count
$hinweis  = @($results | Where-Object Stufe -eq 'Hinweis').Count

Write-Host ''
if ($kritisch + $warnung -eq 0) {
    Write-Host "  Ergebnis: keine Warnung, $hinweis Hinweis(e)." -ForegroundColor Green
    $exitCode = 0
}
else {
    Write-Host "  Ergebnis: $kritisch kritisch, $warnung Warnung(en), $hinweis Hinweis(e)." -ForegroundColor Yellow
    $exitCode = 1
}
Write-Host ''

if ($PassThru) { $results }
exit $exitCode
#endregion
