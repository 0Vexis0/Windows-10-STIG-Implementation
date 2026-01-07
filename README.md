## Windows 10 STIG Implementation

<img width="595" height="387" alt="image" src="https://github.com/user-attachments/assets/14aee9d1-7c98-405c-9394-bb835eafdb6d" />



# STIGs (Security Technical Implementation Guides)

**STIGs** are configuration standards published by **DISA (Defense Information Systems Agency)** that define how information systems and software should be securely configured.

They provide detailed guidance for securing systems, covering settings such as:

- Operating system configurations
- Network and firewall rules
- Password policies and account management
- Security controls and auditing

**Purpose:**  
The purpose of STIGs is to reduce vulnerabilities, enforce compliance, and standardize security across systems, ensuring that systems are hardened against attacks and meet DoD or organizational cybersecurity requirements.

**Summary:**  
STIGs are official, prescriptive security baselines for configuring and maintaining secure systems.
----

<img width="1369" height="353" alt="image" src="https://github.com/user-attachments/assets/e3462089-8b8e-4913-85d7-e5a4d39a4be7" />


non-remediated STIG
----

WN10-SO-000250 - STIG ID - STIG path - \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

<img width="1206" height="502" alt="image" src="https://github.com/user-attachments/assets/66b15973-023c-4597-897a-b7964950bf91" />


Remediated STIG #1
----
```powershell WN10-SO-000250 - STIG ID
# Ensure running as Administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit
}

# Define the registry path
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Define all key-value pairs to enforce
$RegistryValues = @{
    "ConsentPromptBehaviorAdmin"       = 0x2
    "ConsentPromptBehaviorUser"        = 0x3
    "DSCAutomationHostEnabled"         = 0x2
    "EnableCursorSuppression"          = 0x1
    "EnableFullTrustStartupTasks"      = 0x2
    "EnableInstallerDetection"         = 0x1
    "EnableLUA"                        = 0x1
    "EnableSecureUIAPaths"             = 0x1
    "EnableUIADesktopToggle"           = 0x0
    "EnableUwpStartupTasks"            = 0x2
    "EnableVirtualization"             = 0x1
    "PromptOnSecureDesktop"            = 0x1
    "SupportFullTrustStartupTasks"     = 0x1
    "SupportUwpStartupTasks"           = 0x1
    "ValidateAdminCodeSignatures"      = 0x0
    "dontdisplaylastusername"          = 0x0
    "legalnoticecaption"                = ""
    "legalnoticetext"                   = ""
    "scforceoption"                     = 0x0
    "shutdownwithoutlogon"              = 0x1
    "undockwithoutlogon"                = 0x1
}

# Ensure registry key exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Apply each value
foreach ($Name in $RegistryValues.Keys) {
    $Value = $RegistryValues[$Name]
    try {
        if ($Value -is [int]) {
            New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        } else {
            New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType String -Force | Out-Null
        }
    } catch {
        Write-Error "Failed to set $Name. $_"
    }
}

# Verification
$Failures = @()
foreach ($Name in $RegistryValues.Keys) {
    try {
        $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
        if ($CurrentValue -ne $RegistryValues[$Name]) {
            $Failures += $Name
        }
    } catch {
        $Failures += $Name
    }
}

if ($Failures.Count -eq 0) {
    Write-Output "SUCCESS: All registry values applied correctly."
} else {
    Write-Error "FAILURE: The following keys did not apply: $($Failures -join ', ')"
}

````


<img width="1284" height="510" alt="image" src="https://github.com/user-attachments/assets/817ffa5b-9b62-4d89-90dd-2a4391fe3a31" />

non-remediated STIG
----

WN10-CC-000145 - STIG ID - STIG path - \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

<img width="1283" height="402" alt="image" src="https://github.com/user-attachments/assets/1f7fb155-5732-4e66-9a92-420b85858dcb" />


Remediated STIG #2
----

# Ensure running as Administrator for all
```powershell WN10-CC-000145 - STIG ID
# Ensure running as Administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit
}

# Registry path and value
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$RegName = "DCSettingIndex"
$RegValue = 1  # Set the desired power setting

# Ensure registry key exists
if (-not (Test-Path $RegPath)) {
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Output "Registry key created."
    } catch {
        Write-Error "Failed to create registry key. $_"
        exit
    }
}

# Apply the setting forcefully
try {
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType DWord -Force | Out-Null
    Write-Output "Registry value set."
} catch {
    Write-Error "Failed to set registry value. $_"
    exit
}

# Verify the change
try {
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $RegName).$RegName
    if ($CurrentValue -eq $RegValue) {
        Write-Output "SUCCESS: DCSettingIndex is configured correctly for STIG WN10-CC-000145."
    } else {
        Write-Error "FAILURE: DCSettingIndex setting did not apply. Current value: $CurrentValue"
    }
} catch {
    Write-Error "ERROR: Unable to read registry value. $_"
}
```
<img width="1339" height="377" alt="image" src="https://github.com/user-attachments/assets/17945366-91de-497e-89b3-fef10539193a" /> 

non-remediated STIG
----

WN10-CC-000030 - STIG ID - STIG path - \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

<img width="1319" height="482" alt="image" src="https://github.com/user-attachments/assets/c33184f1-abfc-40f5-add2-8b980e3762fd" />

Remediated STIG #3
----
```powershell WN10-CC-000030 - STIG ID
# Admin check
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit
}

$RegPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$RegName  = "EnableICMPRedirect"
$RegValue = 0

# Ensure key exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enforce value
New-ItemProperty `
    -Path $RegPath `
    -Name $RegName `
    -Value $RegValue `
    -PropertyType DWord `
    -Force | Out-Null

# Verify
$current = (Get-ItemProperty -Path $RegPath -Name $RegName).$RegName
if ($current -eq $RegValue) {
    Write-Output "SUCCESS: WN10-CC-000030 (ICMP Redirects disabled) is compliant."
} else {
    Write-Error "FAILURE: EnableICMPRedirect is $current"
}
```
<img width="1350" height="394" alt="image" src="https://github.com/user-attachments/assets/b7ba5bf1-2bf0-4ddd-9a57-f0d36a51ad1c" /> 

non-remediated STIG
----

WN10-CC-000230 - STIG ID - STIG path - \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ 

<img width="1335" height="367" alt="image" src="https://github.com/user-attachments/assets/ae2814f9-a194-4ea4-8773-8ce43fe152d7" />

Remediated STIG #4
----

```powershell WN10-CC-000230 - STIG ID
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$ValueName = "PreventOverride"
$ExpectedValue = 1
$Failures = @()

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord -Force

# Validate
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($ActualValue -ne $ExpectedValue) {
    $Failures += "$ValueName"
}

if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: The following keys did not apply: $($Failures -join ', ')"
} else {
    Write-Host "SUCCESS: WN10-CC-000230 is compliant."
}
```
<img width="1364" height="370" alt="image" src="https://github.com/user-attachments/assets/e7c2521d-6e9c-4067-b0dd-d3dabc23ae03" />

non-remediated STIG
----

WN10-CC-000035 - STIG ID - STIG path - \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\

<img width="1302" height="392" alt="image" src="https://github.com/user-attachments/assets/6a9f5970-9956-4e96-9dff-cc376f6a1325" />

Remediated STIG #5
----
```powershell WN10-CC-000035 - STIG ID
$Failures = @()

# Base paths
$NetBTBase = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$InterfacesBase = "$NetBTBase\Interfaces"

# 1. Enforce NoNameReleaseOnDemand
$GlobalValue = "NoNameReleaseOnDemand"
$GlobalExpected = 1

Set-ItemProperty -Path $NetBTBase -Name $GlobalValue -Value $GlobalExpected -Type DWord -Force

$ActualGlobal = (Get-ItemProperty -Path $NetBTBase -Name $GlobalValue -ErrorAction SilentlyContinue).$GlobalValue
if ($ActualGlobal -ne $GlobalExpected) {
    $Failures += "NoNameReleaseOnDemand"
}

# 2. Enforce NetbiosOptions on all Tcpip_* interfaces
$Interfaces = Get-ChildItem -Path $InterfacesBase | Where-Object {
    $_.PSChildName -like "Tcpip_*"
}

foreach ($Interface in $Interfaces) {
    $RegPath = $Interface.PSPath
    $ValueName = "NetbiosOptions"
    $ExpectedValue = 2

    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord -Force

    $ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    if ($ActualValue -ne $ExpectedValue) {
        $Failures += $Interface.PSChildName
    }
}

# 3. Result
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: The following settings did not apply: $($Failures -join ', ')"
} else {
    Write-Host "SUCCESS: WN10-CC-000035 is compliant."
}
```
<img width="1384" height="400" alt="image" src="https://github.com/user-attachments/assets/8a6ca91b-1280-4e60-9916-ffdd45e6f67c" /> 

non-remediated STIG
----

WN10-CC-000355 - STIG ID - STIG path - \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

<img width="1356" height="370" alt="image" src="https://github.com/user-attachments/assets/56991027-1c9d-4ef8-a1ed-2d5a80663b17" /> 

Remediated STIG #6
----
```powershell WN10-CC-000355 - STIG ID
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$ValueName = "DisableRunAs"
$ExpectedValue = 1
$Failures = @()

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord -Force

# Validate
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
if ($ActualValue -ne $ExpectedValue) {
    $Failures += $ValueName
}

# Result
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: The following keys did not apply: $($Failures -join ', ')"
} else {
    Write-Host "SUCCESS: WN10-CC-000355 is compliant."
}
```
<img width="1372" height="363" alt="image" src="https://github.com/user-attachments/assets/c95dbcef-3642-4b7c-90da-ab8f1ed3cf5a" />


non-remediated STIG
----

WN10-CC-000360 - STIG ID - STIG path - \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

<img width="1298" height="420" alt="image" src="https://github.com/user-attachments/assets/7daa8168-ee10-4d90-b19f-464c77ad1891" />


Remediated STIG #7
----
```powershell WN10-CC-000360 - STIG ID
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$ValueName = "AllowDigest"
$ExpectedValue = 0
$Failures = @()

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord -Force

# Validate
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
if ($ActualValue -ne $ExpectedValue) {
    $Failures += $ValueName
}

# Result
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: The following keys did not apply: $($Failures -join ', ')"
} else {
    Write-Host "SUCCESS: WN10-CC-000360 is compliant."
}
```
<img width="1375" height="388" alt="image" src="https://github.com/user-attachments/assets/7d82c83d-c941-4c03-a574-3852e9fd1382" />


non-remediated STIG
----

WN10-CC-000325 - STIG ID - STIG path - \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

<img width="1353" height="338" alt="image" src="https://github.com/user-attachments/assets/e7b7933e-e57b-4348-9bea-20316d1eabdf" />


Remediated STIG #8
----
```powershell WN10-CC-000325 - STIG ID
# WN10-CC-000325 - Disable Automatic Restart Sign-On
# Requires: Administrator

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "DisableAutomaticRestartSignON"
$ExpectedValue = 1
$Failures = @()

# --- Admin check ---
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "FAILURE: Script must be run as Administrator."
    exit 1
}

# --- Ensure registry path exists ---
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# --- Set registry value ---
try {
    New-ItemProperty `
        -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null
}
catch {
    $Failures += $ValueName
}

# --- Validate ---
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($ActualValue -ne $ExpectedValue) {
    $Failures += $ValueName
}

# --- Result ---
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: The following registry values did not apply correctly: $($Failures -join ', ')"
} else {
    Write-Output "SUCCESS: WN10-CC-000325 (Automatic Restart Sign-On disabled) is compliant."
}

```
<img width="1377" height="377" alt="image" src="https://github.com/user-attachments/assets/5d74c2ee-6893-4cbb-b66a-77db364e9d9d" />


non-remediated STIG
----
WN10-CC-000175  WN10-CC-000020 \SOFTWARE\Policies\Microsoft\Windows\AppCompat\

<img width="1356" height="359" alt="image" src="https://github.com/user-attachments/assets/b7f39b87-782d-4813-a5b2-70c0539d7dd4" />

Remediated STIG #9
----
```powershell WN10-CC-000290 - STIG ID
# WN10-CC-000175 - Disable Application Compatibility Inventory
# Expected: DisableInventory = 1
# Scope: HKLM\SOFTWARE\Policies

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$ValueName = "DisableInventory"
$ExpectedValue = 1
$Failures = @()

# --- Admin check ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "FAILURE: Script must be run as Administrator."
    exit 1
}

# --- Ensure registry path exists ---
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# --- Set registry value ---
try {
    New-ItemProperty `
        -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null
}
catch {
    $Failures += $ValueName
}

# --- Validate ---
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($ActualValue -ne $ExpectedValue) {
    $Failures += $ValueName
}

# --- Result ---
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: WN10-CC-000175 did not apply correctly."
} else {
    Write-Output "SUCCESS: WN10-CC-000175 (Application Compatibility Inventory disabled) is compliant."
}
```
<img width="1256" height="450" alt="image" src="https://github.com/user-attachments/assets/40705d56-9959-43da-996a-ff833b36eeb0" />

non-remediated STIG
----

WN10-CC-000020 - STIG ID - STIG path - \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
 
<img width="1393" height="435" alt="image" src="https://github.com/user-attachments/assets/e810a12e-140e-4efb-91c5-22fa07d3b9e3" />

Remediated STIG #10 
----
```powershell  WN10-CC-000020 - STIG ID
# WN10-CC-000020 - Disable IPv6 Source Routing
# Expected: DisableIpSourceRouting = 2
# Requires: Administrator

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ValueName = "DisableIpSourceRouting"
$ExpectedValue = 2
$Failures = @()

# --- Admin check ---
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "FAILURE: Script must be run as Administrator."
    exit 1
}

# --- Ensure registry path exists ---
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# --- Set value ---
try {
    New-ItemProperty `
        -Path $RegPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $ExpectedValue `
        -Force | Out-Null
}
catch {
    $Failures += $ValueName
}

# --- Validate ---
$ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($ActualValue -ne $ExpectedValue) {
    $Failures += $ValueName
}

# --- Result ---
if ($Failures.Count -gt 0) {
    Write-Error "FAILURE: WN10-CC-000020 did not apply correctly."
} else {
    Write-Output "SUCCESS: WN10-CC-000020 (IPv6 source routing disabled) is compliant."
}
```

# Windows 10 STIG Remediation Summary

## Overview
This document summarizes the remediation of multiple **Windows 10 DISA STIG vulnerabilities** identified during a compliance scan.  

**Process used:**
1. Vulnerabilities were first **identified and manually validated** using nessus scan output and registry inspection.
2. Each finding was then **remediated via direct registry configuration**.
3. **PowerShell remediation scripts** were created (with ChatGPT assistance) to enforce, standardize, and verify the required STIG settings.
4. Post-remediation scans confirmed compliance.

This approach demonstrates both **manual hardening knowledge** and **automated remediation capability**.

---

## 🔴 Identified Vulnerabilities (Pre-Remediation)

The following STIGs were initially found **non-compliant** due to missing or misconfigured registry values:

- **WN10-SO-000250** – User Account Control not properly enforced  
- **WN10-CC-000145** – Power policy setting not configured  
- **WN10-CC-000030** – ICMP redirects enabled  
- **WN10-CC-000230** – Microsoft Edge phishing protection override allowed  
- **WN10-CC-000035** – NetBIOS over TCP/IP enabled  
- **WN10-CC-000355** – WinRM RunAs behavior not restricted  
- **WN10-CC-000360** – WinRM Digest authentication allowed  
- **WN10-CC-000325** – Automatic Restart Sign-On enabled  
- **WN10-CC-000175** – Application Compatibility Inventory enabled  
- **WN10-CC-000020** – IPv6 source routing enabled  

Each vulnerability represented a deviation from DISA STIG security baselines and increased system attack surface.

---

## 🟢 Remediation Actions (Post-Remediation)

All vulnerabilities were successfully remediated by enforcing the required registry configurations:

- Registry paths were **validated and created if missing**
- Required **DWORD values were explicitly set**
- Scripts enforced **idempotent behavior** (safe to re-run)
- Each script included **post-write verification logic**
- Administrator privilege checks ensured safe execution

**Example remediation controls applied:**
- UAC secure desktop enforcement
- Network hardening (ICMP, NetBIOS, IPv6 source routing)
- WinRM authentication restrictions
- Browser security policy enforcement
- Power management security controls
- Application telemetry and inventory suppression

All remediations returned **SUCCESS** and were confirmed compliant by follow-up scans.

---

## Result
✅ **All identified STIG vulnerabilities were successfully remediated**  
✅ **System is now compliant with applicable Windows 10 STIG requirements**  
✅ **Manual validation + automated PowerShell enforcement demonstrated**  

This workflow reflects real-world security operations practices:  
**detect → validate → remediate → verify**.
