<#
.SYNOPSIS
    Prüft, ob Apple-Apps die Geräteverwaltung in iTunes sperren, und entfernt sie auf Wunsch.

.DESCRIPTION
    Sobald Apple-Geräte, Apple Music oder Apple TV installiert ist, zeigt iTunes
    nur noch Podcasts und Hörbücher und keine Geräte mehr an.

    Ohne Parameter ändert das Skript nichts. Es listet die drei Apps für das aktuelle
    Benutzerkonto, die installierte iTunes-Variante und die vorhandenen Geräte-Backups.
    Mit -Remove entfernt es die gefundenen Apps und prüft das Ergebnis.

    Läuft in Windows PowerShell 5.1. Administratorrechte sind nicht nötig.

.PARAMETER Remove
    Entfernt die gefundenen Apps für das aktuelle Benutzerkonto.

.EXAMPLE
    .\Test-AppleApps.ps1
    Zeigt den Stand an, ohne etwas zu ändern.

.EXAMPLE
    .\Test-AppleApps.ps1 -Remove -WhatIf
    Zeigt, welche Apps entfernt würden.

.EXAMPLE
    .\Test-AppleApps.ps1 -Remove
    Entfernt die gefundenen Apps.

.NOTES
    Name: Test-AppleApps
    Author: Andreas Bowitz
    Version: 0.1
    LastUpdated: 2026-Nov-03
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remove
)

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Bitte in Windows PowerShell 5.1 starten (powershell.exe), nicht in PowerShell 7.'
}

$apps = @(
    [pscustomobject]@{ App = 'Apple-Geräte'; Paket = 'AppleInc.AppleDevices' }
    [pscustomobject]@{ App = 'Apple Music';  Paket = 'AppleInc.AppleMusicWin' }
    [pscustomobject]@{ App = 'Apple TV';     Paket = 'AppleInc.AppleTVWin' }
)

# --- 1. Apps im aktuellen Benutzerkonto ------------------------------------------
Write-Host "`nKonto: $env:USERDOMAIN\$env:USERNAME"

$status = foreach ($app in $apps) {
    $paket = Get-AppxPackage -Name $app.Paket -ErrorAction Stop
    [pscustomobject]@{
        App         = $app.App
        Paket       = $app.Paket
        Installiert = [bool]$paket
        Version     = ($paket.Version -join ', ')
    }
}
$status | Format-Table -AutoSize

# --- 2. iTunes-Variante ----------------------------------------------------------
$iTunesStore = Get-AppxPackage -Name 'AppleInc.iTunes'
$iTunesKlassisch = Get-ItemProperty -Path @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
) -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'iTunes' }

if ($iTunesStore)     { Write-Host "iTunes aus dem Microsoft Store: $($iTunesStore.Version)" }
if ($iTunesKlassisch) { Write-Host "iTunes mit klassischem Installer: $($iTunesKlassisch.DisplayVersion)" }
if (-not $iTunesStore -and -not $iTunesKlassisch) {
    Write-Warning 'iTunes wurde nicht gefunden.'
}

# --- 3. Geräte-Backups -----------------------------------------------------------
$backupOrdner = @(
    "$env:USERPROFILE\Apple\MobileSync\Backup"
    "$env:APPDATA\Apple Computer\MobileSync\Backup"
)
foreach ($ordner in $backupOrdner) {
    if (Test-Path -Path $ordner) {
        $anzahl = @(Get-ChildItem -Path $ordner -Directory).Count
        Write-Host "Backups in ${ordner}: $anzahl"
    }
    else {
        Write-Host "Backups in ${ordner}: Ordner nicht vorhanden"
    }
}

# --- 4. Entfernen ----------------------------------------------------------------
$gefunden = @($status | Where-Object { $_.Installiert })

if ($gefunden.Count -eq 0) {
    Write-Host "`nKeine der drei Apps gefunden. Die Sperre kommt in diesem Konto nicht von ihnen."
    return
}

if (-not $Remove) {
    Write-Host "`n$($gefunden.Count) App(s) schränken iTunes ein. Zum Entfernen: .\Test-AppleApps.ps1 -Remove"
    return
}

foreach ($app in $gefunden) {
    if ($PSCmdlet.ShouldProcess($app.Paket, 'Remove-AppxPackage')) {
        Get-AppxPackage -Name $app.Paket | Remove-AppxPackage
    }
}

if ($WhatIfPreference) { return }

# --- 5. Kontrolle ----------------------------------------------------------------
$rest = @($gefunden | Where-Object { Get-AppxPackage -Name $_.Paket })

if ($rest.Count -gt 0) {
    Write-Warning "Noch installiert: $($rest.App -join ', ')"
}
else {
    Write-Host "`nAlle gefundenen Apps sind entfernt. Starte Windows neu und stelle iTunes oben links auf Musik."
}
