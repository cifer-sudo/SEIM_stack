# Configuration file path for persistent storage
$configFilePath = "$env:TMP\WazuhAgentConfig.json"

# Agent version
$agentVersion = "4.4.3-1"

# Wazuh Agent package URL and local file path
$wazuhPackageUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$agentVersion.msi"
$wazuhPackageFile = "$env:TMP\wazuh-agent-$agentVersion.msi"

# Default configuration
$defaultConfig = @{
    ServerAddress = "x.x.x.x"
    AgentGroup    = "default"
    Groups        = @("default", "Groupe", "Services", "Tube")
}

# Load or initialize configuration
function Load-Config {
    if (Test-Path -Path $configFilePath) {
        $configJson = Get-Content -Path $configFilePath -Raw
        $config = $configJson | ConvertFrom-Json
    } else {
        $config = $defaultConfig
        Save-Config $config
    }
    return $config
}

function Save-Config {
    param ($config)
    $config | ConvertTo-Json | Set-Content -Path $configFilePath -Encoding UTF8
}

# Check for admin privileges
if (-not ([bool](New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "Please run this script as an Administrator."
    exit 1
}

# ASCII Art for the Wazuh Agent Utility
function Show-ASCIIArt {
    Write-Host "

\ \      / /_ _ _____   _| |__      ___(_)/ _| ___ _ __ 
 \ \ /\ / / _` |_  / | | | '_ \    / __| | |_ / _ \ '__|
  \ V  V / (_| |/ /| |_| | | | |  | (__| |  _|  __/ |   
   \_/\_/ \__,_/___|\__,_|_| |_|___\___|_|_|  \___|_|   
 
" -ForegroundColor Cyan
}

# Display current deployment parameters
function Show-Parameters {
    Write-Host "`nCurrent deployment parameters:" -ForegroundColor Yellow
    Write-Host "----------------------------------------"
    Write-Host "Server Address   : $($config.ServerAddress)"
    Write-Host "Agent Group      : $($config.AgentGroup)"
    Write-Host "Available Groups : $($config.Groups -join ', ')"
    Write-Host "----------------------------------------`n" -ForegroundColor Yellow
}

# Check Wazuh Agent status
function Check-WazuhAgentStatus {
    # Check if WazuhSvc service exists
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Write-Host "[+] Agent is up and running." -ForegroundColor Green
            return "Running"
        } else {
            Write-Host "[!] Agent is installed but not running." -ForegroundColor Yellow
            return "Installed_NotRunning"
        }
    } else {
        # Service does not exist, check if agent app exists in the expected path
        $agentPath = "$env:ProgramFiles\ossec-agent"
        if (Test-Path -Path $agentPath) {
            Write-Host "[!] Agent is installed but not running." -ForegroundColor Yellow
            return "Installed_NotRunning"
        } else {
            Write-Host "[-] Agent is not installed." -ForegroundColor Red
            return "NotInstalled"
        }
    }
}

# Start Wazuh Agent service# Start Wazuh Agent service
function Start-WazuhService {
    try {
        Start-Service -Name "WazuhSvc" -ErrorAction Stop
        Write-Host "[+] Wazuh Agent service started successfully." -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to start Wazuh Agent service: $_" -ForegroundColor Red
    }
}
# Menu for group selection
function Select-Group {
    Write-Host "`nAvailable Groups:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $config.Groups.Count; $i++) {
        Write-Host "$($i + 1) - $($config.Groups[$i])" -ForegroundColor Cyan
    }
    $selection = Read-Host "Select the group by number"
    if ([int]::TryParse($selection, [ref]$null) -and $selection -gt 0 -and $selection -le $config.Groups.Count) {
        $config.AgentGroup = $config.Groups[$selection - 1]
        Write-Host "[+] Selected group: $($config.AgentGroup)" -ForegroundColor Green
        Save-Config $config
    } else {
        Write-Host "[!] Invalid selection. Using default group." -ForegroundColor Yellow
    }
}

# Reachability test for Wazuh Manager
function Test-Reachability {
    param ([string]$ip)
    try {
        $pingResult = Test-Connection -ComputerName $ip -Count 2 -Quiet
        if ($pingResult) {
            Write-Host "Successfully reached Wazuh Manager at $ip."
            return $true
        } else {
            Write-Host "Failed to reach Wazuh Manager at $ip."
            return $false
        }
    } catch {
        Write-Host "Error testing reachability: $_"
        return $false
    }
}

# Install Wazuh Agent
function Install-WazuhAgent {
    $status = Check-WazuhAgentStatus
    switch ($status) {
        "Running" {
            Write-Host "Wazuh Agent is already installed and running."
        }
        "Installed_NotRunning" {
            Write-Host "Wazuh Agent is installed but not running. Starting service..."
            Start-WazuhService
        }
        "NotInstalled" {
            # Download Wazuh Agent package if not already cached
            if (!(Test-Path -Path $wazuhPackageFile)) {
                Write-Host "Downloading Wazuh Agent package..."
                try {
                    Invoke-WebRequest -Uri $wazuhPackageUrl -OutFile $wazuhPackageFile -ErrorAction Stop
                    Write-Host "Downloaded Wazuh Agent package successfully."
                } catch {
                    Write-Host "Failed to download Wazuh Agent package: $_"
                    return
                }
            } else {
                Write-Host "Using cached Wazuh Agent installer at $wazuhPackageFile."
            }

            Write-Host "Starting Wazuh Agent installation with group: $($config.AgentGroup)"
            try {
                $arguments = @(
                    "/i"
                    "`"$wazuhPackageFile`""
                    "/quiet"
                    "WAZUH_MANAGER=`"$($config.ServerAddress)`""
                    "WAZUH_AGENT_GROUP=`"$($config.AgentGroup)`""
                )
                Start-Process msiexec.exe -ArgumentList $arguments -Wait -NoNewWindow
                Write-Host "Wazuh Agent installed successfully."
                # Start the service after installation
                Start-WazuhService
            } catch {
                Write-Host "Installation failed: $_"
                return
            }
        }
    }
}

# Uninstall Wazuh Agent
function Uninstall-WazuhAgent {
    $status = Check-WazuhAgentStatus
    if ($status -eq "NotInstalled") {
        Write-Host "Wazuh Agent is not installed."
    } else {
        Write-Host "Uninstalling Wazuh Agent..."
        try {
            $productCode = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                Where-Object { $_.DisplayName -eq "Wazuh Agent" }).PSChildName

            if ($productCode) {
                $arguments = @(
                    "/x"
                    "{$productCode}"
                    "/quiet"
                )
                Start-Process msiexec.exe -ArgumentList $arguments -Wait -NoNewWindow
                Write-Host "Wazuh Agent uninstalled successfully."
                # Remove cached installer
                if (Test-Path -Path $wazuhPackageFile) {
                    Remove-Item -Path $wazuhPackageFile -Force
                    Write-Host "Removed cached installer file."
                }
            } else {
                Write-Host "Could not find Wazuh Agent installation information."
            }
        } catch {
            Write-Host "Uninstallation failed: $_"
        }
    }
}

# Add or remove groups in the configuration
function Modify-Groups {
    Write-Host "Current groups: $($config.Groups -join ', ')"
    $choice = Read-Host "Enter '1' to add a group, '2' to remove a group"

    if ($choice -eq "1") {
        $newGroup = Read-Host "Enter new group name"
        if ($config.Groups -notcontains $newGroup) {
            $config.Groups += $newGroup
            Write-Host "Added group: $newGroup"
        } else {
            Write-Host "Group already exists."
        }
    } elseif ($choice -eq "2") {
        $removeGroup = Read-Host "Enter group name to remove"
        if ($config.Groups -contains $removeGroup) {
            $config.Groups = $config.Groups | Where-Object { $_ -ne $removeGroup }
            Write-Host "Removed group: $removeGroup"
        } else {
            Write-Host "Group not found."
        }
    } else {
        Write-Host "Invalid option."
    }

    Save-Config $config
}

# Main Menu
function Show-Menu {
    Clear-Host
    Show-ASCIIArt
    Show-Parameters
    Write-Host "Agent Status:" -ForegroundColor Yellow
    $status = Check-WazuhAgentStatus
    Write-Host "--------------------------------`n" -ForegroundColor Yellow
    Write-Host "Options:" -ForegroundColor Magenta
    Write-Host "1 - Install/Start Agent" -ForegroundColor Blue
    Write-Host "2 - Select Agent Group" -ForegroundColor Blue
    Write-Host "3 - Change Server Address" -ForegroundColor Blue
    Write-Host "4 - Modify Groups" -ForegroundColor Blue
    Write-Host "5 - Uninstall Agent" -ForegroundColor Blue
    Write-Host "0 - Exit" -ForegroundColor Red
}

# Load configuration
$config = Load-Config

# Main loop
do {
    Show-Menu
    $choice = Read-Host "Please select an option (0-5)"

    switch ($choice) {
        "1" {
            if (Test-Reachability -ip $config.ServerAddress) {
                Install-WazuhAgent
            } else {
                Write-Host "Wazuh Manager is unreachable. Check the server address and try again." -ForegroundColor Red
            }
        }
        "2" { Select-Group }
        "3" {
            $newServerAddress = Read-Host "Enter the new Wazuh Manager IP address" -ForegroundColor Cyan
            if ($newServerAddress) {
                $config.ServerAddress = $newServerAddress
                Save-Config $config
                Write-Host "Server address updated to $($config.ServerAddress)."
            } else {
                Write-Host "Invalid input. Server address not changed." -ForegroundColor Red
            }
        }
        "4" { Modify-Groups }
        "5" { Uninstall-WazuhAgent }
        "0" {
            Write-Host "Exiting Wazuh Agent Utility." -ForegroundColor Yellow
            break
        }
        default {
            Write-Host "Invalid option. Please select again." -ForegroundColor Red
        }
    }

    Write-Host "`nPress any key to return to the main menu..."
    [void][System.Console]::ReadKey($true)
} while ($choice -ne "0")
