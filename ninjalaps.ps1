<#
.SYNOPSIS
    Manages a local administrator account, disables the built-in default administrator,
    and rotates the password, storing it securely in NinjaOne custom fields.
    Includes file-based logging with automatic cleanup.

.DESCRIPTION
    This script is designed to be run as a scheduled automation in NinjaOne. It ensures
    a specific local administrator account exists and is enabled, while the well-known
    built-in administrator (SID ending in -500) is disabled.

    A safety check is included to prevent disabling the built-in admin if it is found
    to be running any active processes or scheduled tasks. If a task is found, the script
    will attempt to reassign it to the SYSTEM account before proceeding.

    A server OS safety check is included. By default, the script will not run on servers
    unless explicitly enabled via the $AllowOnServers variable.

    It implements a password rotation policy, generating a new complex password and
    storing it in a secure NinjaOne custom field. A separate date custom field is used
    to track the last password change, ensuring rotation only occurs after a specified
    number of days.

    All actions are logged to a timestamped file in C:\admin, and old logs are automatically
    purged to prevent disk space consumption.

    The script is idempotent, meaning it can be run repeatedly without causing
    errors or unintended changes after the desired state is achieved.

.NOTES
    Author: Gemini
    Version: 2.1
    Created: 2025-08-01
    Modified: 2025-08-01 - Added server OS safety check.

    Requirements:
    - NinjaOne RMM Agent
    - Two NinjaOne custom fields:
        1. A 'Secure' field for the password.
        2. A 'Date' field for tracking the last password set date.
#>

#region --- Configuration Variables ---

# --- Server OS Safety Check ---
# Set to $true to allow this script to run on Windows Server operating systems.
# ProductType 1 = Workstation, 2 = Domain Controller, 3 = Server
# By default, this is disabled to prevent accidental changes on critical servers.
[bool]$AllowOnServers = $false

# --- Account Settings ---
# The desired username for the managed local administrator account.
[string]$NewAdminName = 'corpadmin'
# The desired length for the randomly generated password.
[int]$PasswordLength = 16

# --- NinjaOne Custom Field Settings ---
# The machine-readable name of the SECURE custom field for the password.
# Example: 'adminPasswordSecure'
[string]$SecureFieldName = 'adminPasswordSecure'
# The machine-readable name of the DATE custom field for tracking password age.
# Example: 'adminPasswordLastSet'
[string]$DateFieldName = 'adminPasswordLastSet'

# --- Password Rotation Policy ---
# The maximum age of the password in days. A new password will be generated
# if the last rotation date exceeds this value.
[int]$PwdMaxAgeDays = 30

# --- Logging Settings ---
[string]$LogDirectory = "C:\admin"
[string]$LogFileBaseName = "LAPS-Log"
[int]$LogFilesToKeep = 5

#endregion

#region --- Script Body (Do Not Modify Below) ---

# --- Initialize Logging and Cleanup ---
if (-not (Test-Path $LogDirectory)) {
    try {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    } catch {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] - Failed to create log directory '$LogDirectory'. Exiting."
        exit 1
    }
}

# Define the log file path for this specific run
$timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$script:LogFilePath = Join-Path -Path $LogDirectory -ChildPath "$($LogFileBaseName)-$($timestamp).log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    $formattedMessage = "[{0}] [{1}] - {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    # Write to console for Ninja RMM output
    Write-Host $formattedMessage
    # Write to the log file for troubleshooting
    try {
        $formattedMessage | Out-File -FilePath $script:LogFilePath -Append -Encoding utf8
    } catch {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] - Failed to write to log file '$($script:LogFilePath)'."
    }
}

# Cleanup old log files
try {
    $oldLogs = Get-ChildItem -Path $LogDirectory -Filter "$($LogFileBaseName)-*.log" |
               Sort-Object CreationTime -Descending |
               Select-Object -Skip $LogFilesToKeep

    if ($oldLogs) {
        Write-Log "Performing cleanup of old log files..."
        foreach ($log in $oldLogs) {
            Write-Log "Removing old log file: $($log.FullName)"
            Remove-Item -Path $log.FullName -Force
        }
    }
} catch {
    Write-Log -Level "WARN" -Message "An error occurred during log file cleanup: $_"
}
# --- End Logging Initialization ---

# --- Pre-flight Safety Checks ---
# Check if running on a server OS and if it's allowed
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($osInfo.ProductType -ne 1 -and -not $AllowOnServers) {
        Write-Log -Level "WARN" -Message "This is a server OS (ProductType: $($osInfo.ProductType)) and the script is not configured to run on servers. Exiting."
        exit 0
    }
} catch {
    Write-Log -Level "ERROR" -Message "Could not determine Operating System type. Exiting to be safe. Error: $_"
    exit 1
}

# --- Step 1: Disable the built-in Administrator account (SID ending in -500) ---
try {
    $builtInAdmin = Get-CimInstance -Class Win32_UserAccount -Filter "SID LIKE '%-500'"
    if ($builtInAdmin) {
        if ($builtInAdmin.Disabled) {
            Write-Log "Built-in administrator account '$($builtInAdmin.Name)' is already disabled."
        } else {
            # --- SAFETY CHECK STARTS HERE ---
            Write-Log "Performing safety check before disabling built-in admin '$($builtInAdmin.Name)'..."
            $isBuiltInAdminInUse = $false
            $reasons = @()

            # Check Scheduled Tasks
            Write-Log "Checking for Scheduled Tasks running as '$($builtInAdmin.Name)'..."
            try {
                $conflictingTasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq $builtInAdmin.Name -or $_.Principal.UserId -eq $builtInAdmin.SID }
                if ($conflictingTasks) {
                    $unresolvedConflicts = $false
                    foreach ($task in $conflictingTasks) {
                        if ($task.TaskName -like "*OneDrive Reporting Task*") {
                            Write-Log -Level "WARN" -Message "Found known conflicting task: '$($task.TaskName)'. Attempting to reassign to 'SYSTEM' account."
                            try {
                                $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
                                Set-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Principal $principal
                                Write-Log "Successfully reassigned task '$($task.TaskName)' to run as SYSTEM."
                            } catch {
                                Write-Log -Level "ERROR" -Message "Failed to reassign task '$($task.TaskName)'. It will remain a conflict. Error: $_"
                                $unresolvedConflicts = $true
                                $reasons += "Scheduled Task: $($task.TaskName) (reassignment failed)"
                            }
                        } else {
                            Write-Log -Level "WARN" -Message "Found UNKNOWN conflicting task: '$($task.TaskName)'. This task will not be changed automatically."
                            $unresolvedConflicts = $true
                            $reasons += "Scheduled Task: $($task.TaskName) (unknown)"
                        }
                    }
                    if ($unresolvedConflicts) {
                        $isBuiltInAdminInUse = $true
                    }
                }
            } catch {
                Write-Log -Level "WARN" -Message "Could not check scheduled tasks. Error: $_"
            }

            # Check Running Processes
            Write-Log "Checking for running processes owned by '$($builtInAdmin.Name)'..."
            try {
                $conflictingProcesses = @()
                $processes = Get-CimInstance -ClassName Win32_Process
                foreach ($process in $processes) {
                    try {
                        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
                        if ($owner.User -eq $builtInAdmin.Name) {
                            $conflictingProcesses += "$($process.Name) (PID: $($process.ProcessId))"
                        }
                    } catch {
                        # Ignore errors for processes we can't query (e.g., system idle)
                    }
                }
                if ($conflictingProcesses.Count -gt 0) {
                    $isBuiltInAdminInUse = $true
                    $processNames = $conflictingProcesses -join ', '
                    $reasons += "Running Processes: $processNames"
                }
            } catch {
                 Write-Log -Level "WARN" -Message "Could not check running processes. Error: $_"
            }

            # --- Conditionally Disable Account ---
            if ($isBuiltInAdminInUse) {
                $reasonString = $reasons -join '; '
                Write-Log -Level "WARN" -Message "SAFETY CHECK FAILED: Skipping disable of built-in admin '$($builtInAdmin.Name)' because it is in use. Reason(s): $reasonString"
            } else {
                Write-Log "Safety check passed. Disabling built-in administrator account '$($builtInAdmin.Name)'."
                Disable-LocalUser -SID $builtInAdmin.SID
                Write-Log "Successfully disabled built-in administrator account '$($builtInAdmin.Name)'."
            }
        }
    } else {
        Write-Log -Level "WARN" -Message "Could not find the built-in administrator account (SID ending in -500)."
    }
} catch {
    Write-Log -Level "ERROR" -Message "An error occurred during built-in admin check: $_"
}

# --- Step 2: Ensure the replacement local admin exists and is enabled ---
$adminUser = $null
try {
    $adminUser = Get-LocalUser -Name $NewAdminName -ErrorAction SilentlyContinue
} catch {
    # This space is intentionally left blank. The $adminUser variable will be null if not found.
}

$passwordRotationNeeded = $false
if (-not $adminUser) {
    Write-Log "Managed admin user '$NewAdminName' does not exist. It will be created."
    $passwordRotationNeeded = $true # Force password generation for new user
} else {
    Write-Log "Managed admin user '$NewAdminName' already exists."
    if (-not $adminUser.Enabled) {
        Write-Log "User '$NewAdminName' is disabled. Enabling now."
        try {
            Enable-LocalUser -Name $NewAdminName
            Write-Log "Successfully enabled user '$NewAdminName'."
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to enable user '$NewAdminName': $_"
        }
    } else {
        Write-Log "User '$NewAdminName' is already enabled."
    }
}

# --- Step 3: Check if password rotation is needed ---
if (-not $passwordRotationNeeded) {
    Write-Log "Checking password age for '$NewAdminName'..."
    $lastSetDateString = Ninja-Property-Get $DateFieldName
    Write-Log -Level "DEBUG" -Message "Raw value retrieved from custom field '$DateFieldName': '$lastSetDateString'"

    if (-not [string]::IsNullOrWhiteSpace($lastSetDateString)) {
        try {
            $lastSetDate = $null
            $trimmedDateString = $lastSetDateString.Trim()

            if ($trimmedDateString -match '^\d+$') {
                Write-Log -Level "DEBUG" -Message "Detected Unix timestamp format."
                $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
                $lastSetDate = $epoch.AddSeconds([long]$trimmedDateString).ToLocalTime()
            } else {
                Write-Log -Level "DEBUG" -Message "Detected string date format."
                $lastSetDate = [datetime]::Parse($trimmedDateString, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
            }

            $daysElapsed = (New-TimeSpan -Start $lastSetDate -End (Get-Date)).TotalDays
            Write-Log "Password was last set on $($lastSetDate.ToString('yyyy-MM-dd')). Days elapsed: $($daysElapsed.ToString('F2'))"

            if ($daysElapsed -gt $PwdMaxAgeDays) {
                Write-Log "Password has expired (Max age: $PwdMaxAgeDays days). Rotation is required."
                $passwordRotationNeeded = $true
            } else {
                Write-Log "Password is still within the valid age. No rotation needed."
            }
        } catch {
            Write-Log -Level "ERROR" -Message "Could not PARSE date value '$($lastSetDateString.Trim())' from custom field '$DateFieldName'. Forcing password rotation. Error: $_"
            $passwordRotationNeeded = $true
        }
    } else {
        Write-Log "Last password set date is not available (field is empty or whitespace). Forcing password rotation."
        $passwordRotationNeeded = $true
    }
}

# --- Step 4: Perform account creation and/or password rotation ---
if ($passwordRotationNeeded) {
    Write-Log "Starting password generation and account update process."

    # Generate a new random password
    $charSet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*'
    $random = New-Object System.Random
    $newPassword = -join (1..$PasswordLength | ForEach-Object { $charSet[$random.Next($charSet.Length)] })
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

    try {
        if (-not $adminUser) {
            # Create the user
            Write-Log "Creating new user '$NewAdminName'."
            $adminUser = New-LocalUser -Name $NewAdminName -Password $securePassword -FullName "Managed Local Administrator" -Description "Managed by NinjaOne Automation."
            Write-Log "User '$NewAdminName' created successfully."

            # Add user to the Administrators group
            Write-Log "Adding '$NewAdminName' to the local 'Administrators' group."
            Add-LocalGroupMember -Group 'Administrators' -Member $NewAdminName
            Write-Log "Successfully added '$NewAdminName' to 'Administrators' group."
        } else {
            # Set the password for the existing user
            Write-Log "Setting new password for existing user '$NewAdminName'."
            Set-LocalUser -Name $NewAdminName -Password $securePassword
            Write-Log "Password successfully updated for '$NewAdminName'."
        }

        # Update NinjaOne custom fields
        Write-Log "Updating NinjaOne custom fields..."
        # Format to yyyy-MM-dd to match NinjaOne's requirement for date fields.
        $isoDate = Get-Date -Format "yyyy-MM-dd"

        Ninja-Property-Set $SecureFieldName $newPassword
        Write-Log "Secure field '$SecureFieldName' updated."

        Ninja-Property-Set $DateFieldName $isoDate
        Write-Log "Date field '$DateFieldName' updated to '$isoDate'."

        Write-Log "Password rotation and account update process completed successfully."

    } catch {
        Write-Log -Level "FATAL" -Message "A critical error occurred during account creation or password update: $_"
        # Clean up the generated password variable from memory
        Remove-Variable newPassword, securePassword -ErrorAction SilentlyContinue
        exit 1
    }
} else {
    Write-Log "System is in the desired state. No changes were made."
}

# Clean up sensitive variables from memory
if (Get-Variable 'newPassword' -ErrorAction SilentlyContinue) { Remove-Variable newPassword }
if (Get-Variable 'securePassword' -ErrorAction SilentlyContinue) { Remove-Variable securePassword }

Write-Log "Script finished."
exit 0
#endregion
