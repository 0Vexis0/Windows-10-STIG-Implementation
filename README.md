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

<img width="1334" height="406" alt="image" src="https://github.com/user-attachments/assets/5d70ddf4-984a-4200-aa5e-87f55d8fffdc" />

Unremiadiated STIG
----

WN10-CC-000185 - STIG ID - STIG path - \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

<img width="1363" height="397" alt="image" src="https://github.com/user-attachments/assets/805a7f3d-92ee-4d70-a5b7-09434c497f8b" />

Remiadiated STIG
----
Remiadiated PsISE script for WN10-CC-000185 - The default autorun behavior must be configured to prevent autorun commands.
----

```powershell

# Ensure script runs as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit
}

# Registry path
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$RegName = "NoDriveTypeAutoRun"
$RegValue = 0xFF  # Disable AutoRun on all drives

# Create key if it doesn't exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force
}

# Set the registry value
Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord

Write-Output "AutoRun behavior set to prevent autorun commands."
````




