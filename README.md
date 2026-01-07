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


Unremiadiated STIG
----

WN10-SO-000250 - STIG ID - STIG path - \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

<img width="1206" height="502" alt="image" src="https://github.com/user-attachments/assets/66b15973-023c-4597-897a-b7964950bf91" />


Remiadiated STIG #1
----
Remiadiated PsISE script for User Account Control must, at minimum, prompt administrators for consent on the secure desktop.
STIG ID: WN10-SO-000250
----

```powershell
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

Unremiadiated STIG
----

WN10-CC-000145 - STIG ID - STIG path - \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

<img width="1283" height="402" alt="image" src="https://github.com/user-attachments/assets/1f7fb155-5732-4e66-9a92-420b85858dcb" />


Remiadiated STIG #2
----

# Ensure running as Administrator
```powershell
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

Unremiadiated STIG
----

WN10-CC-000030 - STIG ID - STIG path -\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\


Remiadiated STIG #3
----
```powershell
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
