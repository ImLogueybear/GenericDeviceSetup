<#
.SYNOPSIS
    Enterprise Device Setup Script

.DESCRIPTION
    This script performs the following setup tasks for enterprise devices:
    1. Enables location services (required for timezone and WiFi functions)
    2. Sets the timezone to US/Eastern
    3. Configures power/screen timeout settings
    4. Renames the device according to naming convention
    5. Sets OEM information (Manufacturer, Support Phone, Hours, Website)
    6. Connects to WiFi network with WPA2 authentication
    7. Starts Windows updates in background (runs in separate window)
    8. [PLACEHOLDER] .NET Framework 3.5 installation (future async implementation)
    9. [PLACEHOLDER] .NET Framework 4.8 Advanced Services installation (future async implementation)
    10. Installs essential software via Chocolatey (Chrome, Adobe Reader, Firefox, VLC)
    11. Removes manufacturer bloatware (Lenovo, Dell, HP)
    12. Disables all startup items (suitable for fresh Windows installations)
    13. Executes additional PowerShell plugins from .plugins folder

.NOTES
    Created: 2025-06-25
    Author: System Administrator
    Requires: PowerShell 5.1 or higher, Administrator privileges
    
    IMPORTANT: Configure the variables below before running this script!
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Set strict mode and error action preference
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

#region Configuration Variables - MODIFY THESE BEFORE RUNNING
# =============================================================================
# CONFIGURATION REQUIRED - Update these variables for your environment
# =============================================================================

# Client identification (Maximum 3 characters each)
$CLIENT_NAME = "MAG"           # Replace with your client abbreviation (3 chars max)
$CLIENT_LOCATION = "HRM"       # Replace with location abbreviation (3 chars max)

# WiFi Network Settings
$WIFI_SSID = "MAG_SECURE"    # Replace with your WiFi network name
$WIFI_PASSWORD = "m@G08W1r3L3ss" # Replace with your WiFi password

# Software packages to install (modify as needed)
$SOFTWARE_PACKAGES = @(
    'chromium',
    'firefox',
    'vlc'
)

# Execution Toggles - set to $false to skip select operations
# When set to $false, Step 7 (Windows Updates) will be skipped and a log entry will indicate it was skipped.
$RunWindowsUpdate = $false

# .NET Framework Async Configuration
$NET_FRAMEWORK_ASYNC_MODE = $true    # Enable async mode for .NET Framework installation
$EnableDotNet = $true                # Control whether .NET setup runs

# =============================================================================
# END CONFIGURATION SECTION
# =============================================================================
#endregion Configuration Variables

#region Self-Elevation

# Auto-elevate script if not running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges. Attempting to elevate..."
    
    try {
        # Build arguments to pass to the elevated process
        $scriptPath = $MyInvocation.MyCommand.Definition
        $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
        
        # Start a new elevated process
        $null = Start-Process -FilePath PowerShell.exe -ArgumentList $arguments -Verb RunAs -PassThru -ErrorAction Stop
        
        # Exit the current non-elevated script
        Write-Host "Elevation successful. Script continuing with administrator privileges." -ForegroundColor Green
        exit 0
    }
    catch {
        Write-Error "Failed to elevate privileges. Please run this script as administrator. Error: $_"
        exit 1
    }
}

#endregion Self-Elevation

#region Functions

function Enable-RebootSuppression {
    <#
    .SYNOPSIS
        Enables comprehensive reboot suppression mechanisms
        
    .DESCRIPTION
        Implements multiple layers of reboot prevention including registry settings,
        process monitoring, and Windows Update configuration to prevent automatic reboots
        during the setup process.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Enabling comprehensive reboot suppression..." -Level Information
        
        # 1. Disable automatic restart for Windows Updates
        $updateRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        if (-not (Test-Path $updateRegPath)) {
            New-Item -Path $updateRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $updateRegPath -Name 'AUOptions' -Value 3 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $updateRegPath -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1 -ErrorAction SilentlyContinue
        
        # 2. Set shutdown reason code to prevent unexpected shutdowns
        $shutdownRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability'
        if (-not (Test-Path $shutdownRegPath)) {
            New-Item -Path $shutdownRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $shutdownRegPath -Name 'ShutdownReasonOn' -Value 0 -ErrorAction SilentlyContinue
        
        # 3. Disable System Restore auto-restart
        $systemRestoreRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        if (-not (Test-Path $systemRestoreRegPath)) {
            New-Item -Path $systemRestoreRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $systemRestoreRegPath -Name 'DisableConfig' -Value 1 -ErrorAction SilentlyContinue
        
        # 4. Configure power management to prevent automatic restart
        try {
            powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0 2>&1 | Out-Null
            powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0 2>&1 | Out-Null
            powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
        }
        catch {
            Write-LogMessage "Power configuration warning: $($_.Exception.Message)" -Level Warning
        }
        
        # 5. Set registry flags to prevent automatic reboot after installations
        $installRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $installRegPath) {
            Remove-Item -Path $installRegPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # 6. Disable Windows Error Reporting restart prompts
        $werRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        if (-not (Test-Path $werRegPath)) {
            New-Item -Path $werRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $werRegPath -Name 'DontShowUI' -Value 1 -ErrorAction SilentlyContinue
        
        Write-LogMessage "Reboot suppression mechanisms enabled successfully" -Level Success
        return $true
    }
    catch {
        Write-LogMessage "Error enabling reboot suppression: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Disable-RebootSuppression {
    <#
    .SYNOPSIS
        Disables reboot suppression mechanisms and restores normal behavior
        
    .DESCRIPTION
        Removes the registry settings and configurations that were put in place
        to prevent automatic reboots, restoring the system to normal operation.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Disabling reboot suppression and restoring normal behavior..." -Level Information
        
        # Restore Windows Update auto-restart settings
        $updateRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        if (Test-Path $updateRegPath) {
            Remove-ItemProperty -Path $updateRegPath -Name 'NoAutoRebootWithLoggedOnUsers' -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $updateRegPath -Name 'AUOptions' -Value 4 -ErrorAction SilentlyContinue
        }
        
        # Restore shutdown reason tracking
        $shutdownRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability'
        if (Test-Path $shutdownRegPath) {
            Set-ItemProperty -Path $shutdownRegPath -Name 'ShutdownReasonOn' -Value 1 -ErrorAction SilentlyContinue
        }
        
        # Restore System Restore settings
        $systemRestoreRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        if (Test-Path $systemRestoreRegPath) {
            Remove-ItemProperty -Path $systemRestoreRegPath -Name 'DisableConfig' -ErrorAction SilentlyContinue
        }
        
        # Restore Windows Error Reporting
        $werRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        if (Test-Path $werRegPath) {
            Remove-ItemProperty -Path $werRegPath -Name 'DontShowUI' -ErrorAction SilentlyContinue
        }
        
        Write-LogMessage "Normal reboot behavior restored" -Level Success
        return $true
    }
    catch {
        Write-LogMessage "Error disabling reboot suppression: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Invoke-SafeFeatureInstallation {
    <#
    .SYNOPSIS
        Safely installs Windows features with enhanced reboot suppression
        
    .DESCRIPTION
        Wraps Windows feature installation with additional safeguards to prevent
        unexpected reboots during the installation process.
        
    .PARAMETER FeatureName
        Name of the Windows feature to install
        
    .PARAMETER DisplayName
        Display name for logging purposes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FeatureName,
        
        [Parameter()]
        [string]$DisplayName = $FeatureName
    )
    
    try {
        Write-LogMessage "Starting safe installation of $DisplayName..." -Level Information
        
        # Check if feature is already enabled
        $featureState = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
        
        if ($null -eq $featureState) {
            Write-LogMessage "Feature $FeatureName not found on this system" -Level Warning
            return $false
        }
        
        if ($featureState.State -eq 'Enabled') {
            Write-LogMessage "$DisplayName is already enabled" -Level Success
            return $true
        }
        
        # Enable additional reboot suppression
        Write-LogMessage "Applying enhanced reboot suppression for $DisplayName..." -Level Information
        Enable-RebootSuppression | Out-Null
        
        # Method 1: Try PowerShell cmdlet with strict no-restart
        Write-LogMessage "Attempting PowerShell method for $DisplayName..." -Level Information
        try {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart -ErrorAction Stop
            
            if ($result.RestartNeeded) {
                Write-LogMessage "$DisplayName installed but restart was flagged (suppressed)" -Level Warning
            } else {
                Write-LogMessage "$DisplayName installed successfully via PowerShell" -Level Success
            }
            return $true
        }
        catch {
            Write-LogMessage "PowerShell method failed for $DisplayName : $($_.Exception.Message)" -Level Warning
        }
        
        # Method 2: Try DISM with enhanced parameters
        Write-LogMessage "Attempting DISM method for $DisplayName..." -Level Information
        try {
            $dismResult = Start-Process -FilePath 'dism.exe' -ArgumentList "/online", "/enable-feature", "/featurename:$FeatureName", "/all", "/norestart", "/quiet" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            
            if ($dismResult.ExitCode -eq 0) {
                Write-LogMessage "$DisplayName installed successfully via DISM" -Level Success
                return $true
            }
            elseif ($dismResult.ExitCode -eq 3010) {
                Write-LogMessage "$DisplayName installed via DISM but restart was requested (suppressed)" -Level Warning
                return $true
            }
            else {
                Write-LogMessage "DISM method failed for $DisplayName. Exit code: $($dismResult.ExitCode)" -Level Warning
            }
        }
        catch {
            Write-LogMessage "DISM method failed for $DisplayName : $($_.Exception.Message)" -Level Warning
        }
        
        return $false
    }
    catch {
        Write-LogMessage "Error in safe feature installation for $DisplayName : $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks if system has pending reboot requirements
        
    .DESCRIPTION
        Examines various registry locations and system state to determine
        if a reboot is pending or required.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $pendingReboot = $false
        $rebootReasons = @()
        
        # Check Windows Update reboot flag
        if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
            $pendingReboot = $true
            $rebootReasons += "Windows Updates"
        }
        
        # Check Component Based Servicing reboot flag
        if (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
            $pendingReboot = $true
            $rebootReasons += "Component Based Servicing"
        }
        
        # Check pending file rename operations
        if (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
            $pendingReboot = $true
            $rebootReasons += "Pending File Operations"
        }
        
        if ($pendingReboot) {
            Write-LogMessage "Pending reboot detected. Reasons: $($rebootReasons -join ', ')" -Level Warning
            return $true
        }
        else {
            Write-LogMessage "No pending reboot detected" -Level Success
            return $false
        }
    }
    catch {
        Write-LogMessage "Error checking pending reboot status: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Write-LogMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Information'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Information' { Write-Host $logMessage -ForegroundColor White }
        'Success'     { Write-Host $logMessage -ForegroundColor Green }
        'Warning'     { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'       { Write-Host $logMessage -ForegroundColor Red }
    }
}

function Test-Configuration {
    [CmdletBinding()]
    param()
    
    $configErrors = @()
    
    # Check client name and location
    if ($CLIENT_NAME -eq "CLI" -or $CLIENT_NAME.Length -eq 0) {
        $configErrors += "CLIENT_NAME must be configured (currently set to default 'CLI')"
    }
    if ($CLIENT_LOCATION -eq "LOC" -or $CLIENT_LOCATION.Length -eq 0) {
        $configErrors += "CLIENT_LOCATION must be configured (currently set to default 'LOC')"
    }
    if ($CLIENT_NAME.Length -gt 3) {
        $configErrors += "CLIENT_NAME must be 3 characters or less (currently $($CLIENT_NAME.Length) characters)"
    }
    if ($CLIENT_LOCATION.Length -gt 3) {
        $configErrors += "CLIENT_LOCATION must be 3 characters or less (currently $($CLIENT_LOCATION.Length) characters)"
    }
    
    # Check WiFi settings
    if ($WIFI_SSID -eq "NETWORK_NAME" -or $WIFI_SSID.Length -eq 0) {
        $configErrors += "WIFI_SSID must be configured (currently set to default 'NETWORK_NAME')"
    }
    if ($WIFI_PASSWORD -eq "PASSWORD123" -or $WIFI_PASSWORD.Length -eq 0) {
        $configErrors += "WIFI_PASSWORD must be configured (currently set to default 'PASSWORD123')"
    }
    
    if ($configErrors.Count -gt 0) {
        Write-LogMessage "Configuration errors found:" -Level Error
        foreach ($configError in $configErrors) {
            Write-LogMessage "  - $configError" -Level Error
        }
        Write-LogMessage "Please edit the configuration variables at the top of this script before running." -Level Error
        return $false
    }
    
    return $true
}

function Set-USEasternTimezone {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Setting timezone to US/Eastern..." -Level Information
        
        # Set the timezone to Eastern Standard Time
        Set-TimeZone -Id 'Eastern Standard Time' -ErrorAction Stop
        
        # Verify the change
        $newTimezone = Get-TimeZone
        if ($newTimezone.Id -eq 'Eastern Standard Time') {
            Write-LogMessage "Successfully set timezone to US/Eastern" -Level Success
            return $true
        }
        else {
            Write-LogMessage "Failed to set timezone. Current timezone is $($newTimezone.Id)" -Level Error
            return $false
        }
    }
    catch {
        Write-LogMessage "Error setting timezone: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-PowerSettings {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Configuring power and screen timeout settings..." -Level Information
        
        # Set screen timeout to 10 minutes (600 seconds) for both AC and battery
        powercfg /change monitor-timeout-ac 10
        powercfg /change monitor-timeout-dc 10
        
        # Set system lock timeout to 15 minutes (900 seconds)
        powercfg /change standby-timeout-ac 15
        powercfg /change standby-timeout-dc 15
        
        # Disable hibernation to save disk space
        powercfg /hibernate off
        
        # Set power button action to sleep
        powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
        powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
        
        # Apply the settings
        powercfg /setactive SCHEME_CURRENT
        
        Write-LogMessage "Power settings configured: Screen timeout 10min, Lock timeout 15min" -Level Success
        return $true
    }
    catch {
        Write-LogMessage "Error configuring power settings: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Rename-ComputerWithConvention {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Renaming computer according to naming convention..." -Level Information
        
        # Get computer serial number
        $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
        if (-not $serialNumber) {
            Write-LogMessage "Could not retrieve computer serial number" -Level Error
            return $false
        }
        
        # Get last 7 characters of serial number
        $lastSevenSerial = if ($serialNumber.Length -ge 7) {
            $serialNumber.Substring($serialNumber.Length - 7)
        } else {
            $serialNumber.PadLeft(7, '0')
        }
        
        # Construct new computer name
        $newComputerName = "$CLIENT_NAME-$CLIENT_LOCATION-$lastSevenSerial".ToUpper()
        
        # Check if name change is needed
        $currentComputerName = $env:COMPUTERNAME
        if ($currentComputerName -eq $newComputerName) {
            Write-LogMessage "Computer name is already correct: $newComputerName" -Level Success
            return $true
        }
        
        Write-LogMessage "Renaming computer from '$currentComputerName' to '$newComputerName' (reboot suppressed)" -Level Information
        
        # Enable reboot suppression before rename
        Enable-RebootSuppression | Out-Null
        
        # Rename the computer with restart suppression
        try {
            Rename-Computer -NewName $newComputerName -Force -Restart:$false -ErrorAction Stop
            Write-LogMessage "Computer renamed successfully. Change will take effect on next manual restart." -Level Success
            
            # Additional registry method to ensure name change is queued properly
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
            Set-ItemProperty -Path $regPath -Name 'ComputerName' -Value $newComputerName.ToUpper() -ErrorAction SilentlyContinue
            
            # Note: Not modifying HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName
            # This prevents immediate conflicts - the ActiveComputerName will be updated on restart
            
            Write-LogMessage "Computer name change queued for next restart (automatic reboot suppressed)" -Level Success
            return $true
        }
        catch {
            Write-LogMessage "Standard rename failed, trying alternative method: $($_.Exception.Message)" -Level Warning
            
            # Alternative method using WMI
            try {
                $computer = Get-WmiObject -Class Win32_ComputerSystem
                $result = $computer.Rename($newComputerName)
                
                if ($result.ReturnValue -eq 0) {
                    Write-LogMessage "Computer renamed successfully using WMI method (reboot suppressed)" -Level Success
                    return $true
                }
                else {
                    Write-LogMessage "WMI rename failed with return code: $($result.ReturnValue)" -Level Error
                    return $false
                }
            }
            catch {
                Write-LogMessage "WMI rename method also failed: $($_.Exception.Message)" -Level Error
                return $false
            }
        }
    }
    catch {
        Write-LogMessage "Error renaming computer: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-OEMInformation {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Setting OEM information..." -Level Information
        
        # Define OEM information
        $oemInfo = @{
            'Manufacturer' = 'CTMS LLC'
            'SupportPhone' = '844-286-7644'
            'SupportHours' = '24/7 365'
            'SupportURL' = 'https://www.ctmsit.com/'
        }
        
        # Registry path for OEM information
        $oemRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
        
        # Create the registry key if it doesn't exist
        if (-not (Test-Path $oemRegistryPath)) {
            Write-LogMessage "Creating OEM information registry key..." -Level Information
            New-Item -Path $oemRegistryPath -Force -ErrorAction Stop | Out-Null
        }
        
        # Set each OEM information value
        foreach ($key in $oemInfo.Keys) {
            Write-LogMessage "Setting OEM $key`: $($oemInfo[$key])" -Level Information
            Set-ItemProperty -Path $oemRegistryPath -Name $key -Value $oemInfo[$key] -ErrorAction Stop
        }
        
        # Verify the changes
        $verification = Get-ItemProperty -Path $oemRegistryPath -ErrorAction SilentlyContinue
        if ($verification) {
            $allSet = $true
            foreach ($key in $oemInfo.Keys) {
                if ($verification.$key -ne $oemInfo[$key]) {
                    $allSet = $false
                    break
                }
            }
            
            if ($allSet) {
                Write-LogMessage "OEM information set successfully" -Level Success
                Write-LogMessage "  - Manufacturer: $($verification.Manufacturer)" -Level Information
                Write-LogMessage "  - Support Phone: $($verification.SupportPhone)" -Level Information
                Write-LogMessage "  - Support Hours: $($verification.SupportHours)" -Level Information
                Write-LogMessage "  - Support URL: $($verification.SupportURL)" -Level Information
                return $true
            }
            else {
                Write-LogMessage "OEM information verification failed" -Level Error
                return $false
            }
        }
        else {
            Write-LogMessage "Could not verify OEM information was set" -Level Error
            return $false
        }
    }
    catch {
        Write-LogMessage "Error setting OEM information: $($_.Exception.Message)" -Level Error
        return $false
    }
}

#region .NET Framework Async Installation Functions

function Test-NetFrameworkAsyncDirectory {
    <#
    .SYNOPSIS
        Ensures the C:\temp directory exists for async logging
    #>
    [CmdletBinding()]
    param()
    
    try {
        $tempPath = 'C:\temp'
        if (-not (Test-Path $tempPath)) {
            Write-LogMessage "Creating C:\temp directory for async logging..." -Level Information
            New-Item -Path $tempPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-LogMessage "Created directory: $tempPath" -Level Success
        } else {
            Write-LogMessage "Directory already exists: $tempPath" -Level Information
        }
        return $tempPath
    }
    catch {
        Write-LogMessage "Failed to create/verify C:\temp directory: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Write-NetFrameworkAsyncLog {
    <#
    .SYNOPSIS
        Writes timestamped log entries to the async log file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter(Mandatory)]
        [string]$LogFilePath,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Information'
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $logEntry = "[$timestamp] [$Level] $Message"
        
        # Write to file
        Add-Content -Path $LogFilePath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
        
        # Also write to console for immediate feedback
        Write-LogMessage $Message -Level $Level
    }
    catch {
        Write-LogMessage "Failed to write to async log: $($_.Exception.Message)" -Level Error
    }
}

function Start-NetFrameworkAsync {
    <#
    .SYNOPSIS
        Main function to start the async .NET Framework setup process
    .DESCRIPTION
        Initiates a background PowerShell job that simulates .NET Framework installation
        with comprehensive logging and status tracking capabilities.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Initializing .NET Framework async installation..." -Level Information
        
        # Ensure temp directory exists
        $tempPath = Test-NetFrameworkAsyncDirectory
        if (-not $tempPath) {
            Write-LogMessage "Cannot create temp directory for async logging" -Level Error
            return $null
        }
        
        # Create unique log file name with timestamp
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $logFileName = "NetFramework-Async-$timestamp.log"
        $logFilePath = Join-Path -Path $tempPath -ChildPath $logFileName
        
        Write-LogMessage "Creating async log file: $logFilePath" -Level Information
        
        # Initialize the log file
        $initialLogEntry = "=== .NET Framework Async Process Log Started ==="
        Set-Content -Path $logFilePath -Value $initialLogEntry -Encoding UTF8 -ErrorAction Stop
        
        # Create the background job script block
        $jobScriptBlock = {
            param($LogFilePath)
            
            # Function to write to log file within the job
            function Write-AsyncLog {
                param($Message, $Level = 'Information')
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
                $logEntry = "[$timestamp] [$Level] $Message"
                Add-Content -Path $LogFilePath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Host $logEntry
            }
            
            try {
                Write-AsyncLog "Starting .NET Framework async process" -Level "Information"
                Write-AsyncLog "Process ID: $PID" -Level "Information"
                Write-AsyncLog "Log file path: $LogFilePath" -Level "Information"
                
                # Simulate initialization phase
                Write-AsyncLog "Initializing .NET Framework installation components..." -Level "Information"
                Start-Sleep -Seconds 2
                
                # Show Windows message box as specified in requirements
                Write-AsyncLog "Displaying test message box..." -Level "Information"
                
                # Load Windows Forms for message box
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
                Write-AsyncLog "Windows Forms assembly loaded successfully" -Level "Success"
                
                # Display the message box
                $messageBoxResult = [System.Windows.Forms.MessageBox]::Show(
                    "Testing .NET Framework Async Process",
                    ".NET Framework Async Installation",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                
                Write-AsyncLog "Message box displayed. User clicked: $messageBoxResult" -Level "Success"
                
                # Simulate completion phase
                Write-AsyncLog "Finalizing .NET Framework async process..." -Level "Information"
                Start-Sleep -Seconds 1
                
                Write-AsyncLog ".NET Framework async process completed successfully" -Level "Success"
                Write-AsyncLog "=== .NET Framework Async Process Log Completed ===" -Level "Information"
                
                # Return success status
                return @{
                    Success = $true
                    Message = "Async .NET Framework process completed successfully"
                    LogFile = $LogFilePath
                    CompletedAt = Get-Date
                }
            }
            catch {
                $errorMessage = "Error in async .NET Framework process: $($_.Exception.Message)"
                Write-AsyncLog $errorMessage -Level "Error"
                Write-AsyncLog "Stack trace: $($_.ScriptStackTrace)" -Level "Error"
                Write-AsyncLog "=== .NET Framework Async Process Log Completed with Errors ===" -Level "Error"
                
                return @{
                    Success = $false
                    Message = $errorMessage
                    LogFile = $LogFilePath
                    CompletedAt = Get-Date
                    Error = $_.Exception
                }
            }
        }
        
        # Start the background job
        Write-LogMessage "Starting background job for .NET Framework async process..." -Level Information
        $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $logFilePath -Name "NetFramework-Async-$timestamp"
        
        if ($job) {
            Write-NetFrameworkAsyncLog -Message "Background job started successfully. Job ID: $($job.Id), Name: $($job.Name)" -LogFilePath $logFilePath -Level "Success"
            Write-LogMessage "Async .NET Framework process started. Job ID: $($job.Id)" -Level Success
            
            # Return job information for status tracking
            return @{
                JobId = $job.Id
                JobName = $job.Name
                LogFilePath = $logFilePath
                StartedAt = Get-Date
                Status = 'Running'
            }
        } else {
            Write-LogMessage "Failed to start background job for .NET Framework async process" -Level Error
            return $null
        }
    }
    catch {
        Write-LogMessage "Error starting .NET Framework async process: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-NetFrameworkAsyncStatus {
    <#
    .SYNOPSIS
        Function to check the status of the async .NET Framework process
    .DESCRIPTION
        Checks the status of a running background job and provides detailed status information
    .PARAMETER AsyncInfo
        The async information object returned by Start-NetFrameworkAsync
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AsyncInfo
    )
    
    try {
        if (-not $AsyncInfo -or -not $AsyncInfo.ContainsKey('JobId')) {
            Write-LogMessage "Invalid async info provided to status check" -Level Error
            return @{ Status = 'Invalid'; Message = 'Invalid async information' }
        }
        
        # Get the job by ID
        $job = Get-Job -Id $AsyncInfo.JobId -ErrorAction SilentlyContinue
        
        if (-not $job) {
            Write-LogMessage "Background job not found (ID: $($AsyncInfo.JobId))" -Level Warning
            return @{
                Status = 'NotFound'
                Message = 'Background job not found'
                JobId = $AsyncInfo.JobId
            }
        }
        
        # Get current job state
        $jobState = $job.State
        $statusInfo = @{
            JobId = $AsyncInfo.JobId
            JobName = $AsyncInfo.JobName
            Status = $jobState
            StartedAt = $AsyncInfo.StartedAt
            LogFilePath = $AsyncInfo.LogFilePath
        }
        
        switch ($jobState) {
            'Running' {
                $statusInfo.Message = 'Async .NET Framework process is still running'
                $statusInfo.IsComplete = $false
                Write-LogMessage "Async .NET Framework process is running (Job ID: $($AsyncInfo.JobId))" -Level Information
            }
            'Completed' {
                # Get job results
                $jobResults = Receive-Job -Job $job -ErrorAction SilentlyContinue
                $statusInfo.Message = 'Async .NET Framework process completed successfully'
                $statusInfo.IsComplete = $true
                $statusInfo.Success = $true
                $statusInfo.Results = $jobResults
                Write-LogMessage "Async .NET Framework process completed successfully" -Level Success
            }
            'Failed' {
                $jobResults = Receive-Job -Job $job -ErrorAction SilentlyContinue
                $statusInfo.Message = 'Async .NET Framework process failed'
                $statusInfo.IsComplete = $true
                $statusInfo.Success = $false
                $statusInfo.Results = $jobResults
                $statusInfo.Error = $job.JobStateInfo.Reason
                Write-LogMessage "Async .NET Framework process failed: $($job.JobStateInfo.Reason.Message)" -Level Error
            }
            'Stopped' {
                $statusInfo.Message = 'Async .NET Framework process was stopped'
                $statusInfo.IsComplete = $true
                $statusInfo.Success = $false
                Write-LogMessage "Async .NET Framework process was stopped" -Level Warning
            }
            default {
                $statusInfo.Message = "Async .NET Framework process state: $jobState"
                $statusInfo.IsComplete = $false
                Write-LogMessage "Async .NET Framework process state: $jobState" -Level Information
            }
        }
        
        # Add runtime information
        if ($AsyncInfo.StartedAt) {
            $statusInfo.Runtime = (Get-Date) - $AsyncInfo.StartedAt
            $statusInfo.RuntimeSeconds = [math]::Round($statusInfo.Runtime.TotalSeconds, 2)
        }
        
        return $statusInfo
    }
    catch {
        Write-LogMessage "Error checking async .NET Framework status: $($_.Exception.Message)" -Level Error
        return @{
            Status = 'Error'
            Message = "Error checking status: $($_.Exception.Message)"
            JobId = $AsyncInfo.JobId
            Error = $_.Exception
        }
    }
}

function Wait-NetFrameworkCompletion {
    <#
    .SYNOPSIS
        Function to wait for async .NET Framework process completion
    .DESCRIPTION
        Waits for the background job to complete with optional timeout and progress reporting
    .PARAMETER AsyncInfo
        The async information object returned by Start-NetFrameworkAsync
    .PARAMETER TimeoutSeconds
        Maximum time to wait in seconds (default: 300 = 5 minutes)
    .PARAMETER ShowProgress
        Whether to show periodic progress updates
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AsyncInfo,
        
        [Parameter()]
        [int]$TimeoutSeconds = 300,
        
        [Parameter()]
        [switch]$ShowProgress
    )
    
    try {
        Write-LogMessage "Waiting for .NET Framework async process to complete..." -Level Information
        
        if (-not $AsyncInfo -or -not $AsyncInfo.ContainsKey('JobId')) {
            Write-LogMessage "Invalid async info provided to wait function" -Level Error
            return @{ Success = $false; Message = 'Invalid async information' }
        }
        
        $job = Get-Job -Id $AsyncInfo.JobId -ErrorAction SilentlyContinue
        if (-not $job) {
            Write-LogMessage "Background job not found (ID: $($AsyncInfo.JobId))" -Level Error
            return @{ Success = $false; Message = 'Background job not found' }
        }
        
        $startTime = Get-Date
        $timeoutTime = $startTime.AddSeconds($TimeoutSeconds)
        $lastProgressTime = $startTime
        
        Write-LogMessage "Waiting for job completion (Timeout: $TimeoutSeconds seconds)" -Level Information
        
        while ((Get-Date) -lt $timeoutTime) {
            $currentStatus = Get-NetFrameworkAsyncStatus -AsyncInfo $AsyncInfo
            
            if ($currentStatus.IsComplete) {
                # Job completed - get final results
                $finalResults = Receive-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                
                $completionInfo = @{
                    Success = $currentStatus.Success
                    Message = $currentStatus.Message
                    Results = $finalResults
                    Runtime = $currentStatus.Runtime
                    RuntimeSeconds = $currentStatus.RuntimeSeconds
                    LogFilePath = $AsyncInfo.LogFilePath
                    CompletedAt = Get-Date
                }
                
                if ($currentStatus.Success) {
                    Write-LogMessage "Async .NET Framework process completed successfully in $($currentStatus.RuntimeSeconds) seconds" -Level Success
                } else {
                    Write-LogMessage "Async .NET Framework process completed with errors in $($currentStatus.RuntimeSeconds) seconds" -Level Error
                }
                
                return $completionInfo
            }
            
            # Show progress if requested
            if ($ShowProgress -and ((Get-Date) - $lastProgressTime).TotalSeconds -ge 5) {
                $elapsed = (Get-Date) - $startTime
                Write-LogMessage "Still waiting... Elapsed: $([math]::Round($elapsed.TotalSeconds, 1))s, Status: $($currentStatus.Status)" -Level Information
                $lastProgressTime = Get-Date
            }
            
            Start-Sleep -Seconds 1
        }
        
        # Timeout reached
        Write-LogMessage "Timeout reached waiting for .NET Framework async process" -Level Warning
        
        # Try to stop the job gracefully
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-LogMessage "Error cleaning up timed-out job: $($_.Exception.Message)" -Level Warning
        }
        
        return @{
            Success = $false
            Message = "Timeout reached after $TimeoutSeconds seconds"
            Runtime = (Get-Date) - $startTime
            LogFilePath = $AsyncInfo.LogFilePath
            TimedOut = $true
        }
    }
    catch {
        Write-LogMessage "Error waiting for .NET Framework completion: $($_.Exception.Message)" -Level Error
        return @{
            Success = $false
            Message = "Error waiting for completion: $($_.Exception.Message)"
            Error = $_.Exception
        }
    }
}

#endregion .NET Framework Async Installation Functions

function Connect-WiFiNetwork {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SSID,
        
        [Parameter(Mandatory)]
        [string]$Password,
        
        [Parameter()]
        [ValidateSet('WPA2PSK', 'WPA3SAE', 'WPA', 'open')]
        [string]$Authentication = 'WPA2PSK',
        
        [Parameter()]
        [ValidateSet('AES', 'TKIP', 'none')]
        [string]$Encryption = 'AES'
    )
    
    try {
        Write-LogMessage "Checking for WiFi capability..." -Level Information
        
        # Check if device has WiFi adapters
        $wifiAdapters = Get-NetAdapter -Physical | Where-Object {
            $_.InterfaceDescription -like "*Wireless*" -or
            $_.InterfaceDescription -like "*WiFi*" -or
            $_.InterfaceDescription -like "*802.11*" -or
            $_.Name -like "*Wi-Fi*" -or
            $_.Name -like "*Wireless*"
        }
        
        # Ensure we have an array and check for adapters
        $wifiAdapters = @($wifiAdapters)
        if ($wifiAdapters.Count -eq 0) {
            Write-LogMessage "No WiFi adapters detected on this device. Skipping WiFi configuration." -Level Information
            return $true  # Return true since this isn't an error - device just doesn't have WiFi
        }
        
        # Check if any WiFi adapter is enabled
        $enabledWifiAdapters = @($wifiAdapters | Where-Object { $_.Status -eq 'Up' -or $_.AdminStatus -eq 'Up' })
        if ($enabledWifiAdapters.Count -eq 0) {
            Write-LogMessage "WiFi adapters found but none are enabled. Skipping WiFi configuration." -Level Warning
            return $true  # Return true since this isn't a critical error
        }
        
        Write-LogMessage "WiFi capability detected. Found $($wifiAdapters.Count) WiFi adapter(s)." -Level Information
        Write-LogMessage "Connecting to WiFi network '$SSID'..." -Level Information
        
        # Create WiFi profile XML
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$SSID</name>
    <SSIDConfig>
        <SSID>
            <name>$SSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$Authentication</authentication>
                <encryption>$Encryption</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$Password</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@

        # Save profile to temporary file
        $tempFile = [System.IO.Path]::GetTempFileName()
        $profileXml | Out-File -FilePath $tempFile -Encoding ASCII -ErrorAction Stop
        
        try {
            # Add WiFi profile
            $addProfileResult = netsh wlan add profile filename="$tempFile" 2>&1
            
            if ($addProfileResult -match 'is added on interface') {
                Write-LogMessage "WiFi profile for '$SSID' added successfully" -Level Success
            }
            else {
                Write-LogMessage "Failed to add WiFi profile: $addProfileResult" -Level Error
                return $false
            }
            
            # Connect to the network
            $connectResult = netsh wlan connect name="$SSID" 2>&1
            
            if ($connectResult -match 'Connection request was completed successfully') {
                Write-LogMessage "Successfully connected to WiFi network '$SSID'" -Level Success
                
                # Brief wait for network connectivity to stabilize
                Write-LogMessage "Waiting for network connectivity to stabilize..." -Level Information
                Start-Sleep -Seconds 5
                
                # Quick connectivity test
                $connectivityTest = Test-NetConnection -ComputerName '8.8.8.8' -InformationLevel Quiet -ErrorAction SilentlyContinue
                if ($connectivityTest) {
                    Write-LogMessage "Network connectivity verified" -Level Success
                    return $true
                }
                else {
                    Write-LogMessage "Network connected but connectivity test failed" -Level Warning
                    return $true
                }
            }
            else {
                Write-LogMessage "Failed to connect to WiFi network: $connectResult" -Level Error
                return $false
            }
        }
        finally {
            # Clean up temporary file
            if (Test-Path $tempFile) {
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-LogMessage "Error connecting to WiFi network: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Install-ChocolateyPackageManager {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Checking if Chocolatey is installed..." -Level Information
        
        # Check if Chocolatey is already installed
        $chocoCommand = Get-Command choco -ErrorAction SilentlyContinue
        if ($chocoCommand) {
            Write-LogMessage "Chocolatey is already installed at $($chocoCommand.Source)" -Level Success
            return $true
        }
        
        Write-LogMessage "Installing Chocolatey package manager..." -Level Information
        
        # Set security protocol
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        
        # Test internet connectivity before attempting download
        $connectivityTest = Test-NetConnection -ComputerName 'community.chocolatey.org' -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
        if (-not $connectivityTest) {
            Write-LogMessage "Cannot reach community.chocolatey.org. Waiting 15 seconds and retrying..." -Level Warning
            Start-Sleep -Seconds 15
            
            $connectivityTest = Test-NetConnection -ComputerName 'community.chocolatey.org' -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
            if (-not $connectivityTest) {
                Write-LogMessage "Still cannot reach Chocolatey servers. Network connectivity issue." -Level Error
                return $false
            }
        }
        
        # Install Chocolatey
        $installScript = Invoke-RestMethod -Uri 'https://community.chocolatey.org/install.ps1' -UseBasicParsing -ErrorAction Stop
        Invoke-Expression $installScript
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
        
        # Verify installation
        $chocoCommand = Get-Command choco -ErrorAction SilentlyContinue
        if ($chocoCommand) {
            Write-LogMessage "Chocolatey installed successfully" -Level Success
            return $true
        }
        else {
            Write-LogMessage "Failed to install Chocolatey - command not found after installation" -Level Error
            return $false
        }
    }
    catch {
        Write-LogMessage "Error installing Chocolatey: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Install-SoftwarePackages {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$PackageNames
    )
    
    try {
        Write-LogMessage "Installing software packages: $($PackageNames -join ', ')" -Level Information
        
        # Ensure Chocolatey is installed
        if (-not (Install-ChocolateyPackageManager)) {
            Write-LogMessage "Cannot install software packages without Chocolatey" -Level Error
            return $false
        }
        
        $successCount = 0
        $totalCount = $PackageNames.Count
        
        # Install each package
        foreach ($package in $PackageNames) {
            Write-LogMessage "Installing $package..." -Level Information
            
            try {
                # Install package with auto-confirmation and reduced output
                $installProcess = Start-Process -FilePath 'choco' -ArgumentList "install $package -y --limit-output --no-progress" -Wait -PassThru -NoNewWindow -ErrorAction Stop
                
                # Check exit codes (0 = success, 1641/3010 = success with restart required)
                if ($installProcess.ExitCode -eq 0 -or $installProcess.ExitCode -eq 1641 -or $installProcess.ExitCode -eq 3010) {
                    if ($installProcess.ExitCode -eq 0) {
                        Write-LogMessage "$package installed successfully" -Level Success
                    } else {
                        Write-LogMessage "$package installed successfully (restart required)" -Level Success
                    }
                    $successCount++
                }
                else {
                    Write-LogMessage "Failed to install $package. Exit code: $($installProcess.ExitCode)" -Level Error
                }
            }
            catch {
                Write-LogMessage "Exception installing $package : $($_.Exception.Message)" -Level Error
            }
        }
        
        Write-LogMessage "Software installation completed. $successCount of $totalCount packages installed successfully." -Level Information
        return ($successCount -eq $totalCount)
    }
    catch {
        Write-LogMessage "Error in software installation process: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Remove-ManufacturerBloatware {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Removing manufacturer bloatware..." -Level Information
        
        # Define bloatware patterns for different manufacturers
        $bloatwarePatterns = @{
            'Lenovo' = @(
                '*Lenovo Vantage*', '*Lenovo Welcome*', '*Lenovo Utility*', '*Lenovo ID*',
                '*Lenovo Companion*', '*Lenovo App Explorer*', '*Lenovo System Update*',
                '*Lenovo PowerDVD*', '*Lenovo Photos*', '*Lenovo Migration Assistant*'
            )
            'Dell' = @(
                '*Dell Update*', '*Dell Command*', '*Dell SupportAssist*', '*Dell Customer Connect*',
                '*Dell Product Registration*', '*Dell Help*', '*Dell Backup*', '*My Dell*',
                '*Dell Power Manager*', '*Dell Optimizer*', '*Dell Cinema*', '*Dell Mobile Connect*'
            )
            'HP' = @(
                '*HP Support Assistant*', '*HP Documentation*', '*HP Registration Service*',
                '*HP Software Setup*', '*HP Sure*', '*HP Audio*', '*HP Connection Optimizer*',
                '*HP JumpStart*', '*HP Security Update Service*', '*HP System Information*',
                '*HP Touchpoint*', '*HP Quick Drop*', '*HP Smart*'
            )
        }
        
        $removedCount = 0
        
        # Remove traditional Win32 applications
        Write-LogMessage "Checking for manufacturer Win32 applications..." -Level Information
        
        foreach ($manufacturer in $bloatwarePatterns.Keys) {
            $patterns = $bloatwarePatterns[$manufacturer]
            
            foreach ($pattern in $patterns) {
                $apps = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
                    $_.Name -like $pattern -or ($_.Vendor -like "*$manufacturer*" -and $_.Name -notlike "*Driver*" -and $_.Name -notlike "*BIOS*")
                }
                
                foreach ($app in $apps) {
                    Write-LogMessage "Uninstalling Win32 app: $($app.Name)" -Level Information
                    
                    try {
                        $uninstallResult = $app.Uninstall()
                        
                        if ($uninstallResult.ReturnValue -eq 0) {
                            Write-LogMessage "$($app.Name) uninstalled successfully" -Level Success
                            $removedCount++
                        }
                        else {
                            Write-LogMessage "Failed to uninstall $($app.Name). Return code: $($uninstallResult.ReturnValue)" -Level Warning
                        }
                    }
                    catch {
                        Write-LogMessage "Exception uninstalling $($app.Name): $($_.Exception.Message)" -Level Warning
                    }
                }
            }
        }
        
        # Remove UWP/AppX packages
        Write-LogMessage "Checking for manufacturer UWP applications..." -Level Information
        $manufacturerUwpApps = Get-AppxPackage -AllUsers | Where-Object { 
            $_.Name -like '*Lenovo*' -or $_.Name -like '*Dell*' -or $_.Name -like '*HP*' -or
            $_.Publisher -like '*Lenovo*' -or $_.Publisher -like '*Dell*' -or $_.Publisher -like '*HP*'
        }
        
        foreach ($uwpApp in $manufacturerUwpApps) {
            # Skip essential system apps
            if ($uwpApp.Name -like '*Driver*' -or $uwpApp.Name -like '*Firmware*') {
                Write-LogMessage "Skipping essential app: $($uwpApp.Name)" -Level Information
                continue
            }
            
            Write-LogMessage "Removing UWP app: $($uwpApp.Name)" -Level Information
            
            try {
                Remove-AppxPackage -Package $uwpApp.PackageFullName -ErrorAction Stop
                Write-LogMessage "$($uwpApp.Name) removed successfully" -Level Success
                $removedCount++
            }
            catch {
                Write-LogMessage "Failed to remove $($uwpApp.Name): $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-LogMessage "Manufacturer bloatware removal completed. Removed $removedCount applications." -Level Success
        return $true
    }
    catch {
        Write-LogMessage "Error removing manufacturer bloatware: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Disable-StartupItems {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Disabling all startup items (suitable for fresh Windows installations)..." -Level Information
        
        $disabledCount = 0
        $failedCount = 0
        
        # Process all registry startup locations
        $registryPaths = @(
            @{Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'User'}
            @{Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'Machine'}
            @{Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'User'}
            @{Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Machine'}
        )
        
        foreach ($regInfo in $registryPaths) {
            if (Test-Path $regInfo.Path) {
                Write-LogMessage "Processing $($regInfo.Scope) startup items in $($regInfo.Path)" -Level Information
                
                $startupItems = Get-ItemProperty -Path $regInfo.Path -ErrorAction SilentlyContinue
                
                if ($startupItems) {
                    $properties = @($startupItems.PSObject.Properties | Where-Object {
                        $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')
                    })
                    
                    if ($properties.Count -gt 0) {
                        foreach ($prop in $properties) {
                            Write-LogMessage "Disabling startup item: $($prop.Name) (Command: $($prop.Value))" -Level Information
                            
                            try {
                                Remove-ItemProperty -Path $regInfo.Path -Name $prop.Name -ErrorAction Stop
                                $disabledCount++
                                Write-LogMessage "$($prop.Name) disabled successfully" -Level Success
                            }
                            catch {
                                $failedCount++
                                Write-LogMessage "Failed to disable $($prop.Name): $($_.Exception.Message)" -Level Warning
                            }
                        }
                    }
                }
                else {
                    Write-LogMessage "No startup items found in $($regInfo.Path)" -Level Information
                }
            }
            else {
                Write-LogMessage "Registry path not found: $($regInfo.Path)" -Level Information
            }
        }
        
        # Process startup folder items
        $startupFolders = @(
            @{Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Scope = 'User'}
            @{Path = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"; Scope = 'Machine'}
        )
        
        foreach ($folderInfo in $startupFolders) {
            if (Test-Path $folderInfo.Path) {
                Write-LogMessage "Processing $($folderInfo.Scope) startup folder: $($folderInfo.Path)" -Level Information
                
                $folderItems = @(Get-ChildItem -Path $folderInfo.Path -ErrorAction SilentlyContinue)
                
                if ($folderItems.Count -gt 0) {
                    foreach ($item in $folderItems) {
                        Write-LogMessage "Removing startup item: $($item.Name) from startup folder" -Level Information
                        
                        try {
                            Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                            $disabledCount++
                            Write-LogMessage "$($item.Name) removed successfully from startup folder" -Level Success
                        }
                        catch {
                            $failedCount++
                            Write-LogMessage "Failed to remove $($item.Name) from startup folder: $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
                else {
                    Write-LogMessage "No startup items found in folder: $($folderInfo.Path)" -Level Information
                }
            }
            else {
                Write-LogMessage "Startup folder not found: $($folderInfo.Path)" -Level Information
            }
        }
        
        Write-LogMessage "Startup items cleanup completed. Disabled: $disabledCount, Failed: $failedCount" -Level Success
        
        if ($disabledCount -eq 0 -and $failedCount -eq 0) {
            Write-LogMessage "No startup items were found to disable" -Level Information
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Error disabling startup items: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Start-WindowsUpdatesAsync {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Starting Windows updates in separate process..." -Level Information
        
        # Create temporary script for Windows updates
        $updateScriptPath = Join-Path -Path $env:TEMP -ChildPath "WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        
        $updateScriptContent = @"
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'

function Write-UpdateLog {
    param([string]`$Message, [string]`$Level = 'Information')
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    `$logMessage = "[`$timestamp] [`$Level] `$Message"
    
    switch (`$Level) {
        'Information' { Write-Host `$logMessage -ForegroundColor White }
        'Success'     { Write-Host `$logMessage -ForegroundColor Green }
        'Warning'     { Write-Host `$logMessage -ForegroundColor Yellow }
        'Error'       { Write-Host `$logMessage -ForegroundColor Red }
    }
}

try {
    Write-UpdateLog "Starting Windows Updates process..." -Level Information
    Write-UpdateLog "Window will remain open to show progress..." -Level Information
    
    # Check if PSWindowsUpdate module is available
    `$psWindowsUpdate = Get-Module -Name PSWindowsUpdate -ListAvailable -ErrorAction SilentlyContinue
    
    if (`$psWindowsUpdate) {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Write-UpdateLog "Using PSWindowsUpdate module for update management" -Level Information
        
        # Get all updates including optional and driver updates
        `$allUpdates = Get-WUList -MicrosoftUpdate -IncludeRecommended -ErrorAction SilentlyContinue
        `$optionalUpdates = Get-WUList -IsInstalled:`$false -IsHidden:`$false -CategoryIDs @('28bc880e-0592-4cbf-8f95-c79b17911d5f') -ErrorAction SilentlyContinue
        
        `$totalUpdates = @()
        if (`$allUpdates) { `$totalUpdates += `$allUpdates }
        if (`$optionalUpdates) { `$totalUpdates += `$optionalUpdates }
        
        `$uniqueUpdates = `$totalUpdates | Sort-Object Title -Unique
        
        if (`$uniqueUpdates.Count -eq 0) {
            Write-UpdateLog "No updates found. System is up to date." -Level Success
        }
        else {
            Write-UpdateLog "Found `$(`$uniqueUpdates.Count) update(s) (including optional and driver updates). Installing..." -Level Information
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IncludeRecommended -AutoReboot:`$false -ErrorAction Stop
            Write-UpdateLog "Windows updates installed successfully" -Level Success
        }
    }
    else {
        Write-UpdateLog "Using Windows Update COM objects" -Level Information
        
        `$updateSession = New-Object -ComObject Microsoft.Update.Session
        `$updateSearcher = `$updateSession.CreateUpdateSearcher()
        
        `$searchQueries = @(
            "IsInstalled=0 and Type='Software' and IsHidden=0",
            "IsInstalled=0 and Type='Driver' and IsHidden=0",
            "IsInstalled=0 and BrowseOnly=0 and IsHidden=0"
        )
        
        `$allSearchResults = @()
        
        foreach (`$query in `$searchQueries) {
            Write-UpdateLog "Searching for updates with query: `$query" -Level Information
            try {
                `$searchResult = `$updateSearcher.Search(`$query)
                if (`$searchResult.Updates.Count -gt 0) {
                    `$allSearchResults += `$searchResult.Updates
                    Write-UpdateLog "Found `$(`$searchResult.Updates.Count) update(s) with this search" -Level Information
                }
            }
            catch {
                Write-UpdateLog "Search query failed: `$query. Error: `$(`$_.Exception.Message)" -Level Warning
            }
        }
        
        `$uniqueUpdates = @()
        `$seenUpdateIDs = @()
        
        foreach (`$update in `$allSearchResults) {
            if (`$update.Identity.UpdateID -notin `$seenUpdateIDs) {
                `$uniqueUpdates += `$update
                `$seenUpdateIDs += `$update.Identity.UpdateID
            }
        }
        
        if (`$uniqueUpdates.Count -eq 0) {
            Write-UpdateLog "No updates found. System is up to date." -Level Success
        }
        else {
            Write-UpdateLog "Found `$(`$uniqueUpdates.Count) total unique update(s) (software, driver, and optional)" -Level Information
            
            `$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            
            foreach (`$update in `$uniqueUpdates) {
                if (-not `$update.IsDownloaded) {
                    `$updateType = if (`$update.Type -eq 1) { "Software" } elseif (`$update.Type -eq 2) { "Driver" } else { "Other" }
                    Write-UpdateLog "Adding `$updateType update to download list: `$(`$update.Title)" -Level Information
                    `$null = `$updatesToDownload.Add(`$update)
                }
            }
            
            if (`$updatesToDownload.Count -gt 0) {
                Write-UpdateLog "Downloading `$(`$updatesToDownload.Count) update(s)..." -Level Information
                
                `$downloader = `$updateSession.CreateUpdateDownloader()
                `$downloader.Updates = `$updatesToDownload
                `$downloadResult = `$downloader.Download()
                
                if (`$downloadResult.ResultCode -eq 2) {
                    Write-UpdateLog "Updates downloaded successfully" -Level Success
                }
                else {
                    Write-UpdateLog "Failed to download updates. Result code: `$(`$downloadResult.ResultCode)" -Level Error
                    exit 1
                }
            }
            
            `$updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            
            foreach (`$update in `$uniqueUpdates) {
                if (`$update.IsDownloaded) {
                    `$updateType = if (`$update.Type -eq 1) { "Software" } elseif (`$update.Type -eq 2) { "Driver" } else { "Other" }
                    Write-UpdateLog "Adding `$updateType update to install list: `$(`$update.Title)" -Level Information
                    `$null = `$updatesToInstall.Add(`$update)
                }
            }
            
            if (`$updatesToInstall.Count -gt 0) {
                Write-UpdateLog "Installing `$(`$updatesToInstall.Count) update(s)..." -Level Information
                
                `$installer = `$updateSession.CreateUpdateInstaller()
                `$installer.Updates = `$updatesToInstall
                `$installResult = `$installer.Install()
                
                if (`$installResult.ResultCode -eq 2) {
                    Write-UpdateLog "Updates installed successfully" -Level Success
                    
                    if (`$installResult.RebootRequired) {
                        Write-UpdateLog "System restart is required to complete the update process" -Level Warning
                    }
                }
                else {
                    Write-UpdateLog "Failed to install updates. Result code: `$(`$installResult.ResultCode)" -Level Error
                    exit 1
                }
            }
        }
    }
    
    Write-UpdateLog "Windows updates check and installation completed" -Level Success
    Write-UpdateLog "This window will remain open. You can close it manually or it will close after 30 seconds." -Level Information
    Start-Sleep -Seconds 30
}
catch {
    Write-UpdateLog "Error installing Windows updates: `$(`$_.Exception.Message)" -Level Error
    Write-UpdateLog "This window will remain open for 60 seconds to review the error." -Level Information
    Start-Sleep -Seconds 60
    exit 1
}
"@
        
        # Write the update script to temporary file
        Set-Content -Path $updateScriptPath -Value $updateScriptContent -Encoding UTF8 -ErrorAction Stop
        
        # Start the update process in a new visible PowerShell window
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "powershell.exe"
        $processStartInfo.Arguments = "-ExecutionPolicy Bypass -NoProfile -File ""$updateScriptPath"""
        $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
        $processStartInfo.CreateNoWindow = $false
        $processStartInfo.UseShellExecute = $true
        
        $updateProcess = New-Object System.Diagnostics.Process
        $updateProcess.StartInfo = $processStartInfo
        
        $started = $updateProcess.Start()
        
        if ($started) {
            Write-LogMessage "Windows updates process started successfully in separate window (PID: $($updateProcess.Id))" -Level Success
            Write-LogMessage "The main script will continue while updates run in the background" -Level Information
            
            # Clean up the temporary script after a short delay (in background)
            Start-Job -ScriptBlock {
                param($ScriptPath)
                Start-Sleep -Seconds 300  # Wait 5 minutes before cleanup
                Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
            } -ArgumentList $updateScriptPath | Out-Null
            
            return $true
        }
        else {
            Write-LogMessage "Failed to start Windows updates process" -Level Error
            Remove-Item -Path $updateScriptPath -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    catch {
        Write-LogMessage "Error starting Windows updates process: $($_.Exception.Message)" -Level Error
        if (Test-Path $updateScriptPath) {
            Remove-Item -Path $updateScriptPath -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
}


function Invoke-PluginExecution {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Checking for additional plugins..." -Level Information
        
        # Get the plugins directory path
        $pluginsPath = Join-Path -Path $PSScriptRoot -ChildPath '.plugins'
        
        if (-not (Test-Path $pluginsPath)) {
            Write-LogMessage "Plugins directory not found at: $pluginsPath" -Level Information
            Write-LogMessage "No additional plugins to execute." -Level Information
            return $true
        }
        
        # Get all PowerShell script files in the plugins directory
        $pluginFiles = @(Get-ChildItem -Path $pluginsPath -Filter '*.ps1' -ErrorAction SilentlyContinue)
        
        if ($pluginFiles.Count -eq 0) {
            Write-LogMessage "No plugin scripts found in: $pluginsPath" -Level Information
            Write-LogMessage "No additional plugins to execute." -Level Information
            return $true
        }
        
        # Exclude the template file from execution
        $executablePlugins = @($pluginFiles | Where-Object {
            $_.Name -notlike '*Template*' -and $_.Name -notlike '*template*'
        })
        
        if ($executablePlugins.Count -eq 0) {
            Write-LogMessage "Only template files found in plugins directory. No executable plugins to run." -Level Information
            return $true
        }
        
        Write-LogMessage "Found $($executablePlugins.Count) plugin(s) to execute" -Level Information
        
        $pluginResults = @()
        $successCount = 0
        $partialCount = 0
        $failureCount = 0
        $unknownCount = 0
        
        foreach ($plugin in $executablePlugins) {
            Write-LogMessage "Executing plugin: $($plugin.Name)" -Level Information
            
            try {
                # Execute the plugin as a separate PowerShell process
                $pluginPath = $plugin.FullName
                $processArgs = @(
                    '-ExecutionPolicy', 'Bypass'
                    '-NoProfile'
                    '-File', "`"$pluginPath`""
                )
                
                $pluginProcess = Start-Process -FilePath 'PowerShell.exe' -ArgumentList $processArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
                
                $pluginResult = @{
                    Name = $plugin.Name
                    ExitCode = $pluginProcess.ExitCode
                    Status = ''
                }
                
                # Interpret exit codes
                switch ($pluginProcess.ExitCode) {
                    0 {
                        $pluginResult.Status = 'Success'
                        $successCount++
                        Write-LogMessage "Plugin $($plugin.Name) completed successfully" -Level Success
                    }
                    1 {
                        $pluginResult.Status = 'Failure'
                        $failureCount++
                        Write-LogMessage "Plugin $($plugin.Name) failed to complete" -Level Error
                    }
                    2 {
                        $pluginResult.Status = 'Partial Success'
                        $partialCount++
                        Write-LogMessage "Plugin $($plugin.Name) completed with partial success" -Level Warning
                    }
                    3 {
                        $pluginResult.Status = 'Unknown'
                        $unknownCount++
                        Write-LogMessage "Plugin $($plugin.Name) completed with unknown result" -Level Warning
                    }
                    default {
                        $pluginResult.Status = 'Unexpected Exit Code'
                        $unknownCount++
                        Write-LogMessage "Plugin $($plugin.Name) returned unexpected exit code: $($pluginProcess.ExitCode)" -Level Warning
                    }
                }
                
                $pluginResults += $pluginResult
            }
            catch {
                Write-LogMessage "Error executing plugin $($plugin.Name): $($_.Exception.Message)" -Level Error
                $pluginResults += @{
                    Name = $plugin.Name
                    ExitCode = -1
                    Status = 'Execution Error'
                }
                $failureCount++
            }
        }
        
        # Summary of plugin execution
        $totalPlugins = $pluginResults.Count
        Write-LogMessage "Plugin execution summary:" -Level Information
        Write-LogMessage "  - Total plugins executed: $totalPlugins" -Level Information
        Write-LogMessage "  - Successful: $successCount" -Level Information
        Write-LogMessage "  - Partial Success: $partialCount" -Level Information
        Write-LogMessage "  - Failed: $failureCount" -Level Information
        Write-LogMessage "  - Unknown/Other: $unknownCount" -Level Information
        
        # Detailed results
        foreach ($result in $pluginResults) {
            Write-LogMessage "  - $($result.Name): $($result.Status) (Exit Code: $($result.ExitCode))" -Level Information
        }
        
        # Determine overall plugin system success
        # Consider it successful if at least one plugin succeeded and no critical failures
        if ($successCount -gt 0 -and $failureCount -eq 0) {
            Write-LogMessage "Plugin system execution completed successfully" -Level Success
            return $true
        }
        elseif ($successCount -gt 0 -or $partialCount -gt 0) {
            Write-LogMessage "Plugin system execution completed with warnings" -Level Warning
            return $true
        }
        else {
            Write-LogMessage "Plugin system execution encountered significant issues" -Level Warning
            return $false
        }
    }
    catch {
        Write-LogMessage "Error in plugin execution system: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-NetworkConnectivity {
    [CmdletBinding()]
    param()
    
    $testHosts = @('8.8.8.8', 'community.chocolatey.org', 'microsoft.com')
    
    foreach ($testTarget in $testHosts) {
        $result = Test-NetConnection -ComputerName $testTarget -InformationLevel Quiet -ErrorAction SilentlyContinue
        if ($result) {
            Write-LogMessage "Network connectivity verified (tested: $testTarget)" -Level Success
            return $true
        }
    }
    
    Write-LogMessage "Network connectivity test failed for all test hosts" -Level Error
    return $false
}

function Enable-LocationServices {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Checking location services status..." -Level Information
        
        # Check current location service status
        $locationServicePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        
        if (-not (Test-Path $locationServicePath)) {
            Write-LogMessage "Location services registry path not found. Creating..." -Level Information
            New-Item -Path $locationServicePath -Force -ErrorAction Stop | Out-Null
        }
        
        # Get current location service value
        $currentValue = Get-ItemProperty -Path $locationServicePath -Name 'Value' -ErrorAction SilentlyContinue
        
        if ($currentValue -and $currentValue.Value -eq 'Allow') {
            Write-LogMessage "Location services are already enabled" -Level Success
            return $true
        }
        
        Write-LogMessage "Enabling location services..." -Level Information
        
        # Enable location services globally
        Set-ItemProperty -Path $locationServicePath -Name 'Value' -Value 'Allow' -ErrorAction Stop
        
        # Also enable location service in the system settings
        $locationSystemPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
        if (Test-Path $locationSystemPath) {
            Set-ItemProperty -Path $locationSystemPath -Name 'Status' -Value 1 -ErrorAction SilentlyContinue
        }
        
        # Enable location service for current user
        $userLocationPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        if (-not (Test-Path $userLocationPath)) {
            New-Item -Path $userLocationPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $userLocationPath -Name 'Value' -Value 'Allow' -ErrorAction SilentlyContinue
        
        # Start the location service if it's not running
        try {
            $locationService = Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
            if ($locationService -and $locationService.Status -ne 'Running') {
                Write-LogMessage "Starting Windows Location Framework Service..." -Level Information
                Start-Service -Name 'lfsvc' -ErrorAction Stop
                Write-LogMessage "Location service started successfully" -Level Success
            }
        }
        catch {
            Write-LogMessage "Could not start location service, but registry settings have been configured: $($_.Exception.Message)" -Level Warning
        }
        
        # Verify the change
        $verifyValue = Get-ItemProperty -Path $locationServicePath -Name 'Value' -ErrorAction SilentlyContinue
        if ($verifyValue -and $verifyValue.Value -eq 'Allow') {
            Write-LogMessage "Location services enabled successfully" -Level Success
            return $true
        }
        else {
            Write-LogMessage "Failed to verify location services were enabled" -Level Error
            return $false
        }
    }
    catch {
        Write-LogMessage "Error enabling location services: $($_.Exception.Message)" -Level Error
        return $false
    }
}

#endregion Functions

#region Main Script

# Display banner
Write-Host @"
==================================================
     Enterprise Device Setup and Configuration
==================================================
"@ -ForegroundColor Cyan

Write-LogMessage "Starting enterprise device setup script..." -Level Information

# Validate configuration before proceeding
if (-not (Test-Configuration)) {
    Write-LogMessage "Script terminated due to configuration errors." -Level Error
    exit 1
}

Write-LogMessage "Configuration validated. Client: $CLIENT_NAME, Location: $CLIENT_LOCATION" -Level Information

# Initialize results tracking
$results = @{
    LocationServices = $false
    Timezone = $false
    PowerSettings = $false
    ComputerRename = $false
    OEMInfo = $false
    WiFi = $false
    NetFramework35 = $false
    NetFramework48 = $false
    Software = $false
    Bloatware = $false
    Startup = $false
    Updates = $false
    Plugins = $false
}

# Initialize async tracking variables
$netFrameworkAsyncInfo = $null

# Initialize reboot suppression system
Write-LogMessage "Initializing comprehensive reboot suppression system..." -Level Information
Enable-RebootSuppression | Out-Null

# Step 1: Enable location services (required for timezone and WiFi functions)
Write-LogMessage "Step 1: Enabling location services" -Level Information
$results.LocationServices = Enable-LocationServices
if (-not $results.LocationServices) {
    Write-LogMessage "Failed to enable location services. This may cause timezone and WiFi functions to fail. Continuing with other tasks..." -Level Warning
}

# Step 2: Set timezone to US/Eastern
Write-LogMessage "Step 2: Setting timezone to US/Eastern" -Level Information
$results.Timezone = Set-USEasternTimezone
if (-not $results.Timezone) {
    Write-LogMessage "Failed to set timezone. Continuing with other tasks..." -Level Warning
}

# Step 3: Configure power settings
Write-LogMessage "Step 3: Configuring power and screen timeout settings" -Level Information
$results.PowerSettings = Set-PowerSettings
if (-not $results.PowerSettings) {
    Write-LogMessage "Failed to configure power settings. Continuing with other tasks..." -Level Warning
}

# Step 4: Rename computer
Write-LogMessage "Step 4: Renaming computer according to naming convention" -Level Information
$results.ComputerRename = Rename-ComputerWithConvention
if (-not $results.ComputerRename) {
    Write-LogMessage "Failed to rename computer. Continuing with other tasks..." -Level Warning
}

# Step 5: Set OEM information
Write-LogMessage "Step 5: Setting OEM information" -Level Information
$results.OEMInfo = Set-OEMInformation
if (-not $results.OEMInfo) {
    Write-LogMessage "Failed to set OEM information. Continuing with other tasks..." -Level Warning
}

# Step 6: Connect to WiFi network
Write-LogMessage "Step 6: Connecting to WiFi network" -Level Information

# Check if network connectivity already exists before attempting WiFi connection
Write-LogMessage "Checking if network connectivity already exists..." -Level Information
if (Test-NetworkConnectivity) {
    Write-LogMessage "Network connectivity already available, skipping WiFi setup" -Level Information
    $results.WiFi = $true  # Set to true since we already have connectivity
} else {
    Write-LogMessage "No network connectivity detected, proceeding with WiFi connection..." -Level Information
    $results.WiFi = Connect-WiFiNetwork -SSID $WIFI_SSID -Password $WIFI_PASSWORD -Authentication 'WPA2PSK' -Encryption 'AES'
    if (-not $results.WiFi) {
        Write-LogMessage "Failed to connect to WiFi network. Continuing with other tasks..." -Level Warning
    }
    
    # Quick network connectivity verification if WiFi connection succeeded
    if ($results.WiFi) {
        Write-LogMessage "Verifying network connectivity..." -Level Information
        if (-not (Test-NetworkConnectivity)) {
            Write-LogMessage "Network connectivity test failed, but continuing with other tasks..." -Level Warning
        }
    }
}

# Step 7: Start Windows updates (runs in background)
if ($RunWindowsUpdate) {
    Write-LogMessage "Step 7: Starting Windows updates (will run in background)" -Level Information
    $results.Updates = Start-WindowsUpdatesAsync
    if (-not $results.Updates) {
        Write-LogMessage "Failed to start Windows updates process. Continuing with other tasks..." -Level Warning
    }
} else {
    Write-LogMessage "Step 7: Windows updates skipped by configuration" -Level Information
    $results.Updates = 'Skipped'  # Mark as skipped rather than failed
}

# Step 8 and 9: .NET Framework installation (async)
if ($EnableDotNet) {
    if ($NET_FRAMEWORK_ASYNC_MODE) {
        Write-LogMessage "Step 8-9: Starting .NET Framework installation (async mode)" -Level Information
        
        # Start the async .NET Framework process
        $netFrameworkAsyncInfo = Start-NetFrameworkAsync
        
        if ($netFrameworkAsyncInfo) {
            Write-LogMessage "Async .NET Framework process started successfully" -Level Success
            Write-LogMessage "  - Job ID: $($netFrameworkAsyncInfo.JobId)" -Level Information
            Write-LogMessage "  - Log File: $($netFrameworkAsyncInfo.LogFilePath)" -Level Information
            Write-LogMessage "  - Started At: $($netFrameworkAsyncInfo.StartedAt)" -Level Information
            
            # Wait for completion with progress
            Write-LogMessage "Waiting for .NET Framework async process to complete..." -Level Information
            $completionResult = Wait-NetFrameworkCompletion -AsyncInfo $netFrameworkAsyncInfo -TimeoutSeconds 120 -ShowProgress
            
            if ($completionResult.Success) {
                Write-LogMessage "Async .NET Framework installation completed successfully" -Level Success
                Write-LogMessage "  - Runtime: $($completionResult.RuntimeSeconds) seconds" -Level Information
                Write-LogMessage "  - Log File: $($completionResult.LogFilePath)" -Level Information
                
                # Set both .NET Framework results to true for the demo
                $results.NetFramework35 = $true
                $results.NetFramework48 = $true
            } else {
                Write-LogMessage "Async .NET Framework installation failed or timed out" -Level Error
                Write-LogMessage "  - Error: $($completionResult.Message)" -Level Error
                if ($completionResult.LogFilePath) {
                    Write-LogMessage "  - Check log file: $($completionResult.LogFilePath)" -Level Information
                }
                $results.NetFramework35 = $false
                $results.NetFramework48 = $false
            }
        } else {
            Write-LogMessage "Failed to start async .NET Framework process" -Level Error
            $results.NetFramework35 = $false
            $results.NetFramework48 = $false
        }
    } else {
        Write-LogMessage "Step 8-9: .NET Framework installation - Async mode disabled" -Level Information
        $results.NetFramework35 = 'Skipped'
        $results.NetFramework48 = 'Skipped'
    }
} else {
    Write-LogMessage "Step 8-9: .NET Framework installation - Disabled by configuration" -Level Information
    $results.NetFramework35 = 'Disabled'
    $results.NetFramework48 = 'Disabled'
}

# Step 10: Install software via Chocolatey
Write-LogMessage "Step 10: Installing software packages" -Level Information
$results.Software = Install-SoftwarePackages -PackageNames $SOFTWARE_PACKAGES
if (-not $results.Software) {
    Write-LogMessage "Some software packages may not have been installed correctly. Continuing with other tasks..." -Level Warning
}

# Step 11: Remove manufacturer bloatware
Write-LogMessage "Step 11: Removing manufacturer bloatware" -Level Information
$results.Bloatware = Remove-ManufacturerBloatware
if (-not $results.Bloatware) {
    Write-LogMessage "Failed to remove some manufacturer bloatware. Continuing with other tasks..." -Level Warning
}

# Step 12: Disable all startup items
Write-LogMessage "Step 12: Disabling all startup items (suitable for fresh Windows installations)" -Level Information
$results.Startup = Disable-StartupItems
if (-not $results.Startup) {
    Write-LogMessage "Failed to disable some startup items. Continuing with other tasks..." -Level Warning
}

# Step 13: Execute additional plugins
Write-LogMessage "Step 13: Executing additional plugins" -Level Information
$results.Plugins = Invoke-PluginExecution
if (-not $results.Plugins) {
    Write-LogMessage "Some plugins did not execute successfully. Continuing with script completion..." -Level Warning
}

# Script completion summary
Write-LogMessage "Enterprise device setup script completed" -Level Success
Write-LogMessage "Results Summary:" -Level Information
Write-LogMessage "- Location services enabled: $(if ($results.LocationServices) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Timezone set to US/Eastern: $(if ($results.Timezone) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Power settings configured: $(if ($results.PowerSettings) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Computer renamed: $(if ($results.ComputerRename) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- OEM information set: $(if ($results.OEMInfo) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- .NET Framework 3.5 installation: $(if ($results.NetFramework35 -eq 'Skipped') { 'Skipped (async disabled)' } elseif ($results.NetFramework35 -eq 'Disabled') { 'Disabled by configuration' } elseif ($results.NetFramework35) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- .NET Framework 4.8 installation: $(if ($results.NetFramework48 -eq 'Skipped') { 'Skipped (async disabled)' } elseif ($results.NetFramework48 -eq 'Disabled') { 'Disabled by configuration' } elseif ($results.NetFramework48) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- WiFi connection to $WIFI_SSID`: $(if ($results.WiFi) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Software installation: $(if ($results.Software) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Manufacturer bloatware removal: $(if ($results.Bloatware) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Startup items disabled: $(if ($results.Startup) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Windows updates: $(if ($results.Updates -eq 'Skipped') { 'Skipped by configuration' } elseif ($results.Updates) { 'Success' } else { 'Failed' })" -Level Information
Write-LogMessage "- Additional plugins: $(if ($results.Plugins) { 'Success' } else { 'Failed' })" -Level Information

# Check overall success
$overallSuccess = $results.Values -notcontains $false
if ($overallSuccess) {
    Write-LogMessage "All tasks completed successfully!" -Level Success
}
else {
    Write-LogMessage "Some tasks did not complete successfully. Please review the log for details." -Level Warning
}

# Final cleanup and reboot management
Write-LogMessage "Performing final system cleanup..." -Level Information

# Check if any reboots are pending
if (Test-PendingReboot) {
    # Provide more specific information about reboot requirements
    if ($results.Updates -eq 'Skipped') {
        Write-LogMessage "Pending reboot detected (likely from .NET Framework installation or system changes). Windows Updates were skipped." -Level Warning
    } elseif ($results.Updates -eq $true) {
        Write-LogMessage "Pending reboot detected (likely from Windows Updates or .NET Framework installation)." -Level Warning
    } else {
        Write-LogMessage "Pending reboot detected (likely from .NET Framework installation or system changes)." -Level Warning
    }
    Write-LogMessage "IMPORTANT: Please restart the computer manually when convenient to complete all changes." -Level Information
}
else {
    Write-LogMessage "No pending reboots detected. All changes should be active." -Level Success
}

# Restore normal reboot behavior for future operations
Write-LogMessage "Restoring normal system reboot behavior..." -Level Information
Disable-RebootSuppression | Out-Null

# Clean up any remaining background jobs to prevent hanging
Write-LogMessage "Cleaning up background jobs..." -Level Information
$backgroundJobs = Get-Job -ErrorAction SilentlyContinue
if ($backgroundJobs) {
    Write-LogMessage "Found $($backgroundJobs.Count) background job(s) to clean up" -Level Information
    foreach ($job in $backgroundJobs) {
        Write-LogMessage "Stopping job: $($job.Name) (ID: $($job.Id), State: $($job.State))" -Level Information
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-LogMessage "Could not clean up job $($job.Id): $($_.Exception.Message)" -Level Warning
        }
    }
    Write-LogMessage "Background job cleanup completed" -Level Success
}
else {
    Write-LogMessage "No background jobs found to clean up" -Level Information
}

Write-LogMessage "Script execution finished. Reboot suppression has been disabled." -Level Information
Write-LogMessage "MANUAL RESTART RECOMMENDED: Please restart the computer when convenient to ensure all changes take effect." -Level Information

#endregion Main Script 