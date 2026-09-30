#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Wazuh Agent automatische update voor Windows endpoints.

.DESCRIPTION
    Dit script haalt automatisch de nieuwste versie van de Wazuh agent op
    via de Wazuh packages API en installeert deze stil als er een update
    beschikbaar is. Als de agent al up-to-date is, wordt er niets gedaan.

.NOTES
    - Vereist administrator-rechten
    - Vereist internet toegang naar packages.wazuh.com en api.github.com
    - Compatibel met Windows 10/11 en Windows Server 2016+
    - PowerShell 5.1 of hoger

.EXAMPLE
    .\Update-WazuhAgent.ps1
    Controleert en installeert de nieuwste Wazuh agent versie.

.EXAMPLE
    .\Update-WazuhAgent.ps1 -Force
    Installeert de nieuwste versie, ook als de huidige versie al up-to-date is.

.EXAMPLE
    .\Update-WazuhAgent.ps1 -LogPath "C:\Logs\wazuh-update.log"
    Slaat het logboek op naar een aangepast pad.
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [string]$LogPath = "C:\Windows\Temp\wazuh-update.log",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Configuratie ────────────────────────────────────────────────────────────
$Config = @{
    # GitHub releases API voor versie-detectie
    GitHubReleasesUrl  = "https://api.github.com/repos/wazuh/wazuh/releases/latest"

    # Wazuh packages base URL (stabiele MSI URL-structuur)
    PackageBaseUrl     = "https://packages.wazuh.com/4.x/windows"

    # Tijdelijk downloadpad
    TempDir            = $env:TEMP

    # Timeout voor webverzoeken (seconden)
    WebTimeout         = 60

    # Wazuh agent service naam
    ServiceName        = "WazuhSvc"

    # Wazuh installatiemap (standaard)
    InstallPath        = "C:\Program Files (x86)\ossec-agent"
}

# ── Logging ─────────────────────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computer   = $env:COMPUTERNAME
    $logLine    = "[$timestamp] [$computer] [$Level] $Message"

    # Console output met kleur
    $color = switch ($Level) {
        "INFO"    { "Cyan"    }
        "WARN"    { "Yellow"  }
        "ERROR"   { "Red"     }
        "SUCCESS" { "Green"   }
    }
    Write-Host $logLine -ForegroundColor $color

    # Naar logbestand schrijven
    try {
        $logLine | Out-File -FilePath $LogPath -Append -Encoding UTF8
    } catch {
        Write-Warning "Kon niet schrijven naar logbestand: $LogPath"
    }
}

# ── Hulpfuncties ─────────────────────────────────────────────────────────────
function Get-InstalledWazuhVersion {
    <#
    .SYNOPSIS Haalt de geïnstalleerde Wazuh agent versie op via het Windows register.
    #>
    try {
        # Zoek in 32-bit en 64-bit register
        $regPaths = @(
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($path in $regPaths) {
            $entry = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                     Where-Object { $_.PSObject.Properties["DisplayName"] -and $_.DisplayName -like "Wazuh Agent*" } |
                     Select-Object -First 1

            if ($entry) {
                # DisplayVersion is bijv. "4.12.0"
                $version = $entry.DisplayVersion -replace "[^0-9.]", ""
                if ($version) {
                    return [version]$version
                }
            }
        }

        # Fallback: probeer via VERSION bestand in installatiemap
        $versionFile = Join-Path $Config.InstallPath "VERSION"
        if (Test-Path $versionFile) {
            $content = Get-Content $versionFile -Raw
            if ($content -match "v?(\d+\.\d+\.\d+)") {
                return [version]$Matches[1]
            }
        }

        return $null
    } catch {
        Write-Log "Fout bij ophalen geïnstalleerde versie: $_" -Level WARN
        return $null
    }
}

function Get-LatestWazuhVersion {
    <#
    .SYNOPSIS Haalt de nieuwste Wazuh versie op via de GitHub releases API.
    #>
    try {
        Write-Log "Ophalen nieuwste versie via GitHub releases API..."

        $headers = @{
            "User-Agent" = "WazuhAutoUpdater/1.0 (Windows; $env:COMPUTERNAME)"
            "Accept"     = "application/vnd.github.v3+json"
        }

        $response = Invoke-RestMethod `
            -Uri     $Config.GitHubReleasesUrl `
            -Headers $headers `
            -TimeoutSec $Config.WebTimeout `
            -ErrorAction Stop

        # tag_name is bijv. "v4.12.0"
        $tagName = $response.tag_name
        if ($tagName -match "v?(\d+\.\d+\.\d+)") {
            $latest = [version]$Matches[1]
            Write-Log "Nieuwste versie gevonden: $latest"
            return $latest
        }

        throw "Kon geen versienummer parsen uit tag: $tagName"
    } catch {
        Write-Log "Fout bij ophalen nieuwste versie via GitHub: $_" -Level ERROR
        throw
    }
}

function Get-WazuhMsiUrl {
    <#
    .SYNOPSIS Bouwt de download-URL op voor de Wazuh agent MSI.
    #>
    param([version]$Version)

    # Officiele URL-patroon: wazuh-agent-{versie}-1.msi
    $fileName = "wazuh-agent-$($Version.ToString())-1.msi"
    $url       = "$($Config.PackageBaseUrl)/$fileName"

    return @{
        Url      = $url
        FileName = $fileName
    }
}

function Test-UrlExists {
    <#
    .SYNOPSIS Controleert of een URL bereikbaar is (HTTP HEAD).
    #>
    param([string]$Url)

    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method  = "HEAD"
        $req.Timeout = ($Config.WebTimeout * 1000)
        $resp = $req.GetResponse()
        $resp.Close()
        return $true
    } catch {
        return $false
    }
}

function Invoke-WazuhDownload {
    <#
    .SYNOPSIS Download de Wazuh agent MSI met voortgangsindicator.
    #>
    param(
        [string]$Url,
        [string]$DestinationPath
    )

    Write-Log "Downloaden van: $Url"
    Write-Log "Bestemming: $DestinationPath"

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "WazuhAutoUpdater/1.0")

        # Voortgang tonen
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $webClient.DownloadFile($Url, $DestinationPath)
        $stopwatch.Stop()

        $sizeMB = [math]::Round((Get-Item $DestinationPath).Length / 1MB, 2)
        Write-Log "Download voltooid: $sizeMB MB in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s" -Level SUCCESS
    } catch {
        Write-Log "Download mislukt: $_" -Level ERROR
        throw
    } finally {
        $webClient.Dispose()
    }
}

function Install-WazuhMsi {
    <#
    .SYNOPSIS Installeert de Wazuh agent MSI stil (unattended).
    #>
    param([string]$MsiPath)

    if ($DryRun) {
        Write-Log "[DRY RUN] Zou uitvoeren: msiexec.exe /i `"$MsiPath`" /q" -Level WARN
        return
    }

    Write-Log "Installatie starten (stil/unattended)..."
    Write-Log "MSI bestand: $MsiPath"

    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "/q",          # Stil installeren
        "/norestart",  # Niet herstarten
        "/l*v", "`"$($Config.TempDir)\wazuh-msi-install.log`""  # Verbose MSI log
    )

    try {
        $process = Start-Process -FilePath "msiexec.exe" `
                                 -ArgumentList $msiArgs `
                                 -Wait `
                                 -PassThru `
                                 -ErrorAction Stop

        switch ($process.ExitCode) {
            0    { Write-Log "Installatie succesvol voltooid (exit code 0)" -Level SUCCESS }
            3010 { Write-Log "Installatie succesvol, herstart vereist (exit code 3010)" -Level WARN }
            1641 { Write-Log "Installatie succesvol, herstart wordt gestart (exit code 1641)" -Level WARN }
            default {
                throw "MSI installatie mislukt met exit code: $($process.ExitCode)"
            }
        }

        return $process.ExitCode
    } catch {
        Write-Log "Installatie mislukt: $_" -Level ERROR
        throw
    }
}

function Get-WazuhServiceStatus {
    <#
    .SYNOPSIS Controleert de status van de Wazuh agent service.
    #>
    try {
        $svc = Get-Service -Name $Config.ServiceName -ErrorAction Stop
        return $svc.Status
    } catch {
        return "NotFound"
    }
}

# ── Hoofdlogica ──────────────────────────────────────────────────────────────
function Main {
    Write-Log "═══════════════════════════════════════════════════════════════"
    Write-Log "Wazuh Agent Auto-Update gestart"
    Write-Log "Computer: $env:COMPUTERNAME | Gebruiker: $env:USERNAME"
    if ($DryRun) {
        Write-Log "MODUS: DRY RUN - geen wijzigingen worden aangebracht" -Level WARN
    }
    Write-Log "═══════════════════════════════════════════════════════════════"

    $msiPath = $null

    try {
        # 1. Geïnstalleerde versie ophalen
        $installedVersion = Get-InstalledWazuhVersion
        if ($installedVersion) {
            Write-Log "Geïnstalleerde versie: $installedVersion"
        } else {
            Write-Log "Wazuh agent is niet geïnstalleerd op dit systeem. Script wordt afgebroken." -Level ERROR
            exit 1
        }

        # 2. Nieuwste versie ophalen
        $latestVersion = Get-LatestWazuhVersion

        # 3. Vergelijken
        if ($installedVersion -and -not $Force) {
            if ($installedVersion -ge $latestVersion) {
                Write-Log "Wazuh agent is al up-to-date (versie: $installedVersion)" -Level SUCCESS
                Write-Log "Gebruik -Force om toch opnieuw te installeren."
                return
            }
            Write-Log "Update beschikbaar: $installedVersion → $latestVersion" -Level WARN
        } elseif ($Force) {
            Write-Log "Force-modus actief, installatie wordt afgedwongen..." -Level WARN
        }

        # 4. Download-URL opbouwen en controleren
        $msiInfo = Get-WazuhMsiUrl -Version $latestVersion
        Write-Log "Package URL: $($msiInfo.Url)"

        Write-Log "Controleren beschikbaarheid van pakket..."
        if (-not (Test-UrlExists -Url $msiInfo.Url)) {
            throw "Pakket niet bereikbaar: $($msiInfo.Url)"
        }
        Write-Log "Pakket is bereikbaar" -Level SUCCESS

        # 5. Downloaden
        $msiPath = Join-Path $Config.TempDir $msiInfo.FileName
        Invoke-WazuhDownload -Url $msiInfo.Url -DestinationPath $msiPath

        # 6. Service stoppen voor installatie (voorkomt exit code 1603)
        $svcStatusBefore = Get-WazuhServiceStatus
        Write-Log "Wazuh service status vóór installatie: $svcStatusBefore"

        if ($svcStatusBefore -eq "Running" -and -not $DryRun) {
            Write-Log "Wazuh service stoppen voor installatie..."
            try {
                Stop-Service -Name $Config.ServiceName -Force -ErrorAction Stop
                Start-Sleep -Seconds 3
                Write-Log "Wazuh service gestopt" -Level SUCCESS
            } catch {
                Write-Log "Kon service niet stoppen: $_" -Level WARN
            }
        }

        # 7. Systeemvoorbereiding voor installatie
        if (-not $DryRun) {
            # Fix voor MSI error 2738: VBScript runtime registreren onder HKLM (vereist voor SYSTEM-context)
            Write-Log "VBScript runtime registreren onder HKLM (fix error 2738 voor SYSTEM-context)..."
            try {
                $vbsPath  = "$env:SystemRoot\SysWOW64\vbscript.dll"
                $jsPath   = "$env:SystemRoot\SysWOW64\jscript.dll"
                $regBase  = "HKLM:\SOFTWARE\Classes\CLSID"

                # VBScript CLSID: {B54F3741-5B07-11CF-A4B0-00AA004A55E8}
                $vbsClsid = "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}"
                # JScript CLSID:  {F414C260-6AC0-11CF-B6D1-00AA00BBBB58}
                $jsClsid  = "{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}"

                foreach ($entry in @(
                    @{ Clsid = $vbsClsid; Dll = $vbsPath; Name = "VBScript" },
                    @{ Clsid = $jsClsid;  Dll = $jsPath;  Name = "JScript"  }
                )) {
                    $keyPath = "$regBase\$($entry.Clsid)\InprocServer32"
                    if (-not (Test-Path $keyPath)) {
                        New-Item -Path $keyPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $keyPath -Name "(Default)"      -Value $entry.Dll        -ErrorAction Stop
                    Set-ItemProperty -Path $keyPath -Name "ThreadingModel" -Value "Apartment"       -ErrorAction Stop
                    Write-Log "$($entry.Name) geregistreerd onder HKLM: $keyPath" -Level SUCCESS
                }

                # Standaard regsvr32 ook uitvoeren als aanvulling
                Start-Process "regsvr32.exe" -ArgumentList "/s vbscript.dll" -Wait
                Start-Process "regsvr32.exe" -ArgumentList "/s jscript.dll"  -Wait

                Write-Log "VBScript/JScript runtime volledig geregistreerd" -Level SUCCESS
            } catch {
                Write-Log "Kon VBScript runtime niet registreren: $_" -Level WARN
            }

            # Verwijder pending reboot vlag zodat MSI niet blokkeert
            Write-Log "Controleren op pending reboot vlag..."
            try {
                $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                if (Get-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -ErrorAction Stop
                    Write-Log "Pending reboot vlag verwijderd" -Level SUCCESS
                } else {
                    Write-Log "Geen pending reboot vlag gevonden"
                }
            } catch {
                Write-Log "Kon pending reboot vlag niet verwijderen: $_" -Level WARN
            }
        }

        # 8. Installeren
        $exitCode = Install-WazuhMsi -MsiPath $msiPath

        # 9. Service-status na installatie
        if (-not $DryRun) {
            Start-Sleep -Seconds 5
            $svcStatusAfter = Get-WazuhServiceStatus
            Write-Log "Wazuh service status na installatie: $svcStatusAfter"

            # Service starten als deze niet loopt
            if ($svcStatusAfter -ne "Running") {
                Write-Log "Wazuh service starten..."
                try {
                    Start-Service -Name $Config.ServiceName -ErrorAction Stop
                    Write-Log "Wazuh service gestart" -Level SUCCESS
                } catch {
                    Write-Log "Kon service niet starten: $_" -Level WARN
                }
            }

            # Geïnstalleerde versie verifiëren
            Start-Sleep -Seconds 3
            $newVersion = Get-InstalledWazuhVersion
            if ($newVersion) {
                Write-Log "Geverifieerde geïnstalleerde versie: $newVersion" -Level SUCCESS
            }
        }

        Write-Log "═══════════════════════════════════════════════════════════════"
        Write-Log "Update voltooid" -Level SUCCESS
        Write-Log "═══════════════════════════════════════════════════════════════"

    } catch {
        Write-Log "KRITIEKE FOUT: $_" -Level ERROR
        Write-Log "Stacktrace: $($_.ScriptStackTrace)" -Level ERROR
        exit 1

    } finally {
        # Opruimen: tijdelijk MSI-bestand verwijderen
        if ($msiPath -and (Test-Path $msiPath)) {
            try {
                Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
                Write-Log "Tijdelijk bestand verwijderd: $msiPath"
            } catch {
                Write-Log "Kon tijdelijk bestand niet verwijderen: $msiPath" -Level WARN
            }
        }
    }
}

# ── Startpunt ────────────────────────────────────────────────────────────────
Main
