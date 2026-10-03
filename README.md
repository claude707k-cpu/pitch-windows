# pitch-windows

<#
.SYNOPSIS
    Shield — Windows Server defense toolkit.

.DESCRIPTION
    Usage (run as Administrator):
        .\Shield.ps1 -Mode harden              # hardening pass (report-only unless -Apply)
        .\Shield.ps1 -Mode harden -Apply        # hardening pass, apply changes for real
        .\Shield.ps1 -Mode monitor              # live SOC-style dashboard
        .\Shield.ps1 -Mode block                # failed-login review / RDP exposure baseline
        .\Shield.ps1 -Mode block -Apply          # also blocks IPs over the failed-login threshold
        .\Shield.ps1 -Mode remediate             # lockdown: accounts, firewall, suspicious processes
        .\Shield.ps1 -Mode remediate -Apply      # apply remediation for real
        .\Shield.ps1 -Mode incident              # forensic snapshot to C:\SecurityIncidents
        .\Shield.ps1 -Mode telemetry             # export JSON summary for SIEM ingestion
        .\Shield.ps1 -Mode baseline-firewall     # save current firewall rules as the known-good baseline
        .\Shield.ps1 -Mode shield                # run harden -> block -> remediate -> monitor
        .\Shield.ps1 -Mode shield -Apply         # same, applying changes for real

.NOTES
    Run as Administrator. Everything defaults to REPORT-ONLY — pass -Apply to
    make real changes (replaces the old "edit $ApplySettings in the file"
    approach). Test on a snapshot first.
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("harden", "monitor", "block", "remediate", "incident", "telemetry", "baseline-firewall", "shield")]
    [string]$Mode,

    [switch]$Apply
)

# ======================= SETTINGS =======================
$ApplySettings        = [bool]$Apply
$MonitorInterval       = 20
$IncidentFolder        = "C:\SecurityIncidents"
$TelemetryFolder       = "C:\SecurityTelemetry"
$AlertLogPath          = "$TelemetryFolder\alerts.json"
$FirewallBaselinePath  = "$TelemetryFolder\firewall-baseline.json"
$FailedLogonThreshold  = 10

# IPs/subnets that should NEVER be auto-blocked even if they rack up failed logons
# (your own admin workstation, monitoring tools, backup servers, etc.)
$TrustedIPs = @(
    # "10.0.0.5",
    # "192.168.1.0/24"
)

# Directories a legitimate system process should rarely run from.
# A process executing out of one of these paths is worth a second look.
$SuspiciousProcessPaths = @(
    "\\Downloads\\",
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "C:\\Temp\\",
    "C:\\Users\\Public\\"
)
# ==========================================================

$IsDomainController = (Get-WmiObject Win32_OperatingSystem).ProductType -eq 2

function Write-Banner($text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Structured alert logging — appends one JSON object per line to alerts.json
# so a SIEM or log shipper can tail it. This is the "real alert system."
# ---------------------------------------------------------------------------
function Write-Alert {
    param(
        [ValidateSet("INFO","LOW","MEDIUM","HIGH","CRITICAL")]
        [string]$Severity,
        [string]$Type,
        [string]$Message,
        [hashtable]$Extra = @{}
    )

    New-Item -Path $TelemetryFolder -ItemType Directory -Force | Out-Null

    $alert = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        severity  = $Severity
        type      = $Type
        message   = $Message
    }
    foreach ($key in $Extra.Keys) { $alert[$key] = $Extra[$key] }

    $json = $alert | ConvertTo-Json -Compress
    Add-Content -Path $AlertLogPath -Value $json

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Red" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Yellow" }
        default    { "Gray" }
    }
    Write-Host "[$Severity] $Message" -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Check whether an IP falls inside a trusted entry (exact match or CIDR subnet)
# ---------------------------------------------------------------------------
function Test-TrustedIP {
    param([string]$IPAddress)

    foreach ($entry in $TrustedIPs) {
        if ($entry -eq $IPAddress) { return $true }
        if ($entry -match '/') {
            try {
                $parts = $entry -split '/'
                $netIP = [System.Net.IPAddress]::Parse($parts[0])
                $prefixLen = [int]$parts[1]
                $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
                $netBytes = $netIP.GetAddressBytes()
                [Array]::Reverse($ipBytes); [Array]::Reverse($netBytes)
                $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
                $netInt = [BitConverter]::ToUInt32($netBytes, 0)
                $mask = [UInt32]::MaxValue -shl (32 - $prefixLen)
                if (($ipInt -band $mask) -eq ($netInt -band $mask)) { return $true }
            } catch { }
        }
    }
    return $false
}

# ===========================================================================
# HARDEN
# ===========================================================================
function Invoke-Harden {
    Write-Banner "HARDEN: Firewall"
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize
    if ($ApplySettings) {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Alert -Severity INFO -Type "HARDEN" -Message "Firewall enabled, inbound blocked by default on all profiles."
    }

    Write-Banner "HARDEN: Defender"
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | Format-List
    if ($ApplySettings) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Update-MpSignature
        Write-Alert -Severity INFO -Type "HARDEN" -Message "Defender real-time protection enabled, signatures updated."
    }

    Write-Banner "HARDEN: SMBv1"
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | Format-List
    if ($ApplySettings) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Alert -Severity INFO -Type "HARDEN" -Message "SMBv1 disabled."
    }

    Write-Banner "HARDEN: RDP Network Level Authentication"
    $nla = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    Write-Host "NLA required: $($nla -eq 1)"
    if ($ApplySettings) {
        Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Write-Alert -Severity INFO -Type "HARDEN" -Message "RDP NLA enforced."
    }

    Write-Banner "HARDEN: Auditing"
    if ($ApplySettings) {
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        Write-Alert -Severity INFO -Type "HARDEN" -Message "Auditing enabled for logon, account management, policy change."
    } else {
        Write-Host "(report-only — pass -Apply to enable auditing)"
    }

    # Save a firewall baseline right after hardening, so later runs can detect changes.
    if ($ApplySettings) {
        Save-FirewallBaseline
    }
}

# ===========================================================================
# FIREWALL BASELINE + CHANGE DETECTION
# ===========================================================================
function Save-FirewallBaseline {
    New-Item -Path $TelemetryFolder -ItemType Directory -Force | Out-Null
    $rules = Get-NetFirewallRule | Select-Object Name, DisplayName, Direction, Action, Enabled
    $rules | ConvertTo-Json -Depth 3 | Out-File $FirewallBaselinePath -Encoding utf8
    Write-Host "Firewall baseline saved: $($rules.Count) rules recorded to $FirewallBaselinePath"
}

function Test-FirewallChanges {
    if (-not (Test-Path $FirewallBaselinePath)) {
        Write-Host "No firewall baseline found yet. Run '.\Shield.ps1 -Mode baseline-firewall' first,"
        Write-Host "or run '-Mode harden -Apply' once (it saves a baseline automatically)."
        return
    }

    $baseline = Get-Content $FirewallBaselinePath -Raw | ConvertFrom-Json
    $current  = Get-NetFirewallRule | Select-Object Name, DisplayName, Direction, Action, Enabled

    $baselineByName = @{}
    foreach ($r in $baseline) { $baselineByName[$r.Name] = $r }

    $currentByName = @{}
    foreach ($r in $current) { $currentByName[$r.Name] = $r }

    # New rules (in current, not in baseline)
    foreach ($name in $currentByName.Keys) {
        if (-not $baselineByName.ContainsKey($name)) {
            $r = $currentByName[$name]
            $severity = if ($r.Direction -eq "Inbound" -and $r.Action -eq "Allow") { "HIGH" } else { "MEDIUM" }
            Write-Alert -Severity $severity -Type "FIREWALL_CHANGE" `
                -Message "New firewall rule created: $($r.DisplayName)" `
                -Extra @{ rule_name = $r.Name; direction = "$($r.Direction)"; action = "$($r.Action)"; enabled = "$($r.Enabled)" }
        }
    }

    # Deleted rules (in baseline, not in current)
    foreach ($name in $baselineByName.Keys) {
        if (-not $currentByName.ContainsKey($name)) {
            $r = $baselineByName[$name]
            Write-Alert -Severity MEDIUM -Type "FIREWALL_CHANGE" `
                -Message "Firewall rule deleted: $($r.DisplayName)" `
                -Extra @{ rule_name = $r.Name }
        }
    }

    # Modified rules (same name, different action/enabled/direction)
    foreach ($name in $currentByName.Keys) {
        if ($baselineByName.ContainsKey($name)) {
            $old = $baselineByName[$name]
            $new = $currentByName[$name]
            if ("$($old.Action)" -ne "$($new.Action)" -or "$($old.Enabled)" -ne "$($new.Enabled)" -or "$($old.Direction)" -ne "$($new.Direction)") {
                Write-Alert -Severity HIGH -Type "FIREWALL_CHANGE" `
                    -Message "Firewall rule modified: $($new.DisplayName)" `
                    -Extra @{ rule_name = $name; old_action = "$($old.Action)"; new_action = "$($new.Action)"; old_enabled = "$($old.Enabled)"; new_enabled = "$($new.Enabled)" }
            }
        }
    }

    # Whole-firewall disabled check
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        if (-not $p.Enabled) {
            Write-Alert -Severity CRITICAL -Type "FIREWALL_DISABLED" -Message "Firewall profile '$($p.Name)' is DISABLED."
        }
    }
}

# ===========================================================================
# BLOCK — RDP exposure baseline + failed-login detection with trusted-IP allowlist
# ===========================================================================
function Invoke-AntiDDoS {
    Write-Banner "RDP EXPOSURE BASELINE"
    Write-Host "Note: Windows Firewall has no native per-IP rate limiting, so this section"
    Write-Host "does NOT throttle connections. It reports RDP's exposure and, separately,"
    Write-Host "detects and can block IPs with repeated failed logons (see below)."
    Write-Host "For real volumetric DDoS protection, that needs a network-edge service"
    Write-Host "(Azure DDoS Protection, Cloudflare, a WAF) in front of this host — not something"
    Write-Host "a host-level script can provide."

    $rdpRule = Get-NetFirewallRule -DisplayName "Shield-RDP-Exposure-Baseline" -ErrorAction SilentlyContinue
    Write-Host "RDP (3389) firewall exposure rule present: $([bool]$rdpRule)"
    if ($ApplySettings -and -not $rdpRule) {
        New-NetFirewallRule -DisplayName "Shield-RDP-Exposure-Baseline" `
            -Direction Inbound -Protocol TCP -LocalPort 3389 `
            -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Baseline RDP rule recorded (for tracking exposure only — does not add security by itself)."
    }

    Write-Banner "FAILED LOGON REVIEW (brute-force candidates)"
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 -ErrorAction SilentlyContinue
    if ($failedLogons) {
        $byIP = $failedLogons | ForEach-Object {
            ($_.Properties | Where-Object { $_.Value -match '^\d{1,3}(\.\d{1,3}){3}$' }).Value
        } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10

        $byIP | ForEach-Object {
            $trusted = Test-TrustedIP -IPAddress $_.Name
            [PSCustomObject]@{ IP = $_.Name; FailedCount = $_.Count; Trusted = $trusted }
        } | Format-Table -AutoSize

        foreach ($entry in $byIP) {
            $trusted = Test-TrustedIP -IPAddress $entry.Name

            if ($trusted) {
                Write-Host "Skipping $($entry.Name) — on trusted list ($($entry.Count) failed logons ignored)."
                continue
            }

            if ($entry.Count -gt $FailedLogonThreshold) {
                $severity = if ($entry.Count -gt ($FailedLogonThreshold * 3)) { "CRITICAL" } else { "HIGH" }
                Write-Alert -Severity $severity -Type "BRUTE_FORCE" `
                    -Message "$($entry.Count) failed logons from $($entry.Name) (untrusted)" `
                    -Extra @{ source_ip = $entry.Name; count = $entry.Count }

                if ($ApplySettings) {
                    New-NetFirewallRule -DisplayName "Shield-Block-$($entry.Name)" `
                        -Direction Inbound -Action Block -RemoteAddress $entry.Name -ErrorAction SilentlyContinue | Out-Null
                    Write-Alert -Severity $severity -Type "AUTO_BLOCK" `
                        -Message "Blocked $($entry.Name) after $($entry.Count) failed logons" `
                        -Extra @{ source_ip = $entry.Name; count = $entry.Count; action = "BLOCKED" }
                }
            } elseif ($entry.Count -gt 3) {
                Write-Alert -Severity LOW -Type "FAILED_LOGON" `
                    -Message "$($entry.Count) failed logons from $($entry.Name) (below threshold)" `
                    -Extra @{ source_ip = $entry.Name; count = $entry.Count }
            }
        }
    } else {
        Write-Host "No failed logon events found (or auditing not yet enabled — run -Mode harden -Apply first)."
    }

    Write-Banner "FIREWALL CHANGE CHECK"
    Test-FirewallChanges
}

# ===========================================================================
# REMEDIATE — now includes process-path suspicion check
# ===========================================================================
function Invoke-Remediate {
    Write-Banner "REMEDIATE: Guest account"
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
        Write-Host "Guest account enabled: $($guest.Enabled)"
        if ($ApplySettings -and $guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Alert -Severity INFO -Type "REMEDIATE" -Message "Guest account disabled."
        }
    }

    Write-Banner "REMEDIATE: Known-bad process names (weak signal — easily bypassed by renaming)"
    $watchList = @("nc.exe", "ncat.exe", "mimikatz.exe", "psexec.exe")
    $found = Get-Process | Where-Object { $watchList -contains "$($_.ProcessName).exe" }
    if ($found) {
        $found | Select-Object ProcessName, Id, Path | Format-Table -AutoSize
        foreach ($p in $found) {
            Write-Alert -Severity HIGH -Type "SUSPICIOUS_PROCESS" `
                -Message "Known-bad process name running: $($p.ProcessName) (PID $($p.Id))" `
                -Extra @{ process = $p.ProcessName; pid_val = $p.Id; path = "$($p.Path)" }
        }
        if ($ApplySettings) {
            $found | ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Write-Alert -Severity HIGH -Type "AUTO_KILL" -Message "Killed $($_.ProcessName) (PID $($_.Id))"
            }
        }
    } else {
        Write-Host "No known-bad process names currently running."
    }

    Write-Banner "REMEDIATE: Processes running from suspicious paths"
    Write-Host "Checking for processes launched from user-writable / staging directories"
    Write-Host "(Downloads, AppData\Temp, C:\Temp, etc.) — this catches renamed tools that"
    Write-Host "the name-based watchlist above would miss. ALERT ONLY — nothing is killed"
    Write-Host "automatically here, since a legitimate app can run from these paths too."

    $allProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }
    $suspicious = $allProcesses | Where-Object {
        $path = $_.ExecutablePath
        $hit = $false
        foreach ($pattern in $SuspiciousProcessPaths) {
            if ($path -match [regex]::Escape($pattern)) { $hit = $true }
        }
        $hit
    }

    if ($suspicious) {
        $suspicious | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath | Format-Table -AutoSize
        foreach ($p in $suspicious) {
            Write-Alert -Severity MEDIUM -Type "SUSPICIOUS_PATH" `
                -Message "$($p.Name) (PID $($p.ProcessId)) is running from a suspicious path" `
                -Extra @{
                    process   = $p.Name
                    pid_val   = $p.ProcessId
                    parent_pid = $p.ParentProcessId
                    path      = $p.ExecutablePath
                }
        }
    } else {
        Write-Host "No processes currently running from flagged directories."
    }

    Write-Banner "REMEDIATE: Firewall lockdown"
    if ($ApplySettings) {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block
        Write-Alert -Severity INFO -Type "REMEDIATE" -Message "Firewall enforced on all profiles."
    } else {
        Write-Host "(report-only — pass -Apply to enforce)"
    }
}

# ===========================================================================
# MONITOR — now includes periodic firewall-change check
# ===========================================================================
function Invoke-Monitor {
    Write-Host "Live SOC Dashboard — refreshing every $MonitorInterval seconds. Press Ctrl+C to exit." -ForegroundColor Green
    while ($true) {
        Clear-Host
        Write-Host "=========== SHIELD LIVE DASHBOARD — $(Get-Date) ===========" -ForegroundColor Cyan

        Write-Host "`n-- System Health --" -ForegroundColor Yellow
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue
        $mem = Get-CimInstance Win32_OperatingSystem
        $memUsedPct = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 1)
        Write-Host ("CPU: {0:N1}%   Memory used: {1}%" -f $cpu, $memUsedPct)

        Write-Host "`n-- Active Sessions --" -ForegroundColor Yellow
        quser 2>$null

        Write-Host "`n-- Failed Logons (last 50 events) --" -ForegroundColor Yellow
        $failed = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($failed) {
            $recentCount = ($failed | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-10) }).Count
            Write-Host "Failed logons in last 10 min: $recentCount"
            if ($recentCount -gt $FailedLogonThreshold) {
                Write-Alert -Severity HIGH -Type "BRUTE_FORCE" -Message "$recentCount failed logons in the last 10 minutes."
            }
        } else {
            Write-Host "None found (or auditing not yet enabled)."
        }

        Write-Host "`n-- Listening Ports --" -ForegroundColor Yellow
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort | Format-Table -AutoSize

        Write-Host "`n-- Top CPU Processes --" -ForegroundColor Yellow
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU | Format-Table -AutoSize

        Write-Host "`n-- Firewall Change Check --" -ForegroundColor Yellow
        Test-FirewallChanges

        Start-Sleep -Seconds $MonitorInterval
    }
}

# ===========================================================================
# INCIDENT
# ===========================================================================
function Invoke-Incident {
    $folder = "$IncidentFolder\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -Path $folder -ItemType Directory -Force | Out-Null

    Get-Process | Select-Object Name, Id, CPU, StartTime | Export-Csv "$folder\processes.csv" -NoTypeInformation
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv "$folder\network-connections.csv" -NoTypeInformation
    quser 2>$null | Out-File "$folder\logged-on-users.txt"
    Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message | Export-Csv "$folder\recent-security-events.csv" -NoTypeInformation
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, State | Export-Csv "$folder\scheduled-tasks.csv" -NoTypeInformation
    Get-LocalUser -ErrorAction SilentlyContinue | Export-Csv "$folder\local-users.csv" -NoTypeInformation
    Get-NetFirewallRule | Select-Object Name, DisplayName, Direction, Action, Enabled | Export-Csv "$folder\firewall-rules.csv" -NoTypeInformation

    Write-Host "Forensic snapshot saved to: $folder"
    Write-Alert -Severity INFO -Type "INCIDENT_SNAPSHOT" -Message "Forensic snapshot saved to $folder"
}

# ===========================================================================
# TELEMETRY
# ===========================================================================
function Invoke-Telemetry {
    New-Item -Path $TelemetryFolder -ItemType Directory -Force | Out-Null
    $file = "$TelemetryFolder\telemetry-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    $failed = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 200 -ErrorAction SilentlyContinue
    $mem = Get-CimInstance Win32_OperatingSystem

    $data = [ordered]@{
        timestamp         = (Get-Date).ToString("o")
        hostname          = $env:COMPUTERNAME
        memory_used_pct   = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 1)
        failed_logons     = @($failed).Count
        firewall_enabled  = (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }).Count -eq 0
        defender_realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled
        listening_ports   = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique)
        logged_on_users   = @(quser 2>$null)
    }

    $data | ConvertTo-Json -Depth 4 | Out-File $file -Encoding utf8
    Write-Host "Telemetry exported to: $file"
}

# ===========================================================================
# DISPATCH
# ===========================================================================
switch ($Mode) {
    "harden"            { Invoke-Harden }
    "block"             { Invoke-AntiDDoS }
    "remediate"         { Invoke-Remediate }
    "monitor"           { Invoke-Monitor }
    "incident"          { Invoke-Incident }
    "telemetry"         { Invoke-Telemetry }
    "baseline-firewall" { Save-FirewallBaseline }
    "shield" {
        Invoke-Harden
        Invoke-AntiDDoS
        Invoke-Remediate
        Invoke-Monitor
    }
}
