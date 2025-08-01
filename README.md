# NinjaOne LAPS-Style Local Admin Management Script

This PowerShell script provides a robust, LAPS-style solution for managing a local administrator account on Windows endpoints using NinjaOne. It creates and maintains a dedicated local admin account, rotates its password on a schedule, and securely stores the new password in a NinjaOne custom field.

The script is designed to be idempotent and safe for recurring execution as a scheduled task in NinjaOne, ensuring that endpoints automatically maintain a secure state without manual intervention.

## Key Features

* **Disables Built-in Administrator**: Identifies the default administrator account (by its well-known SID ending in -500) and disables it to enhance security.
* **Intelligent Safety Checks**: Before disabling the built-in admin, the script checks for any running processes or scheduled tasks using the account.
    * **Automated Remediation**: If it finds the common "OneDrive Reporting Task," it automatically reassigns it to the `SYSTEM` account to resolve the conflict.
    * **Failsafe**: For any other conflicting tasks or processes, it logs a detailed warning and skips the disable step to prevent outages.
* **Server OS Safety Check**: By default, the script will not run on Windows Server operating systems. This can be overridden with a configuration variable, preventing accidental changes on critical servers.
* **LAPS-Style Password Rotation**: Automatically rotates the managed admin's password only when its age exceeds a configurable threshold (e.g., 30 days).
* **Secure Credential Storage**: Securely stores the managed admin password in a **Secure** NinjaOne custom field using the agent's built-in tools.
* **Robust Logging**: Creates detailed, timestamped log files in `C:\admin` for easy troubleshooting, with automatic cleanup of old logs.
* **Idempotent Design**: Safe to run on a recurring schedule. The script only makes changes when necessary to bring a system into its desired state.

## Requirements

1.  **NinjaOne RMM Agent**: Must be installed on the target endpoints.
2.  **PowerShell 5.1 or higher**: Required for the `Microsoft.PowerShell.LocalAccounts` module.
3.  **Two NinjaOne Custom Fields**:
    * A **Secure** field to store the password.
    * A **Date** field to track the last password rotation date.

## Setup & Configuration

### Step 1a: Create Custom Fields

Navigate to **Administration** -> **Devices** -> **Device Custom Fields** in your NinjaOne instance and create the following two fields:

| Field Type | Display Name                  | Machine Name               |
| :--------- | :---------------------------- | :------------------------- |
| **Secure** | Managed Admin Password        | `adminPasswordSecure`      |
| **Date** | Managed Admin Pwd Last Set    | `adminPasswordLastSet`     |

*Note: You can use different machine names, but you must update them in the script's configuration section.*

### Step 1b: Organize Fields in a Custom Tab

To make these fields easy to find on a device's page, you can group them in a dedicated tab.

1.  Navigate to **Administration** -> **Devices** -> **Roles**.
2.  For the **Managed devices** role, click the ellipsis (**...**) and select **Edit**.
3.  In the top-right corner, click **Manage tabs**.
4.  Click **Add tab** and give it a name, such as `Local Administrator Password`.
5.  Select your new tab from the list.
6.  Click **Add Field** and add the two custom fields you created (`Managed Admin Password` and `Managed Admin Pwd Last Set`).
7.  Click **Save** to apply the changes.

### Step 2: Add and Configure the Script

1.  Navigate to **Administration** -> **Library** -> **Automation**.
2.  Click the **+ Add** button to create a new automation.
3.  Select **New Script**.
4.  Fill out the details (Name, Description, etc.) and select **PowerShell** as the language.
5.  Paste the entire contents of this script into the editor.
6.  In the script editor, modify the variables in the `--- Configuration Variables ---` section to match your environment.
    ```powershell
    # --- Server OS Safety Check ---
    # Set to $true to allow this script to run on Windows Server operating systems.
    [bool]$AllowOnServers = $false

    # --- Account Settings ---
    [string]$NewAdminName = 'corpadmin'
    [int]$PasswordLength = 16

    # --- NinjaOne Custom Field Settings ---
    [string]$SecureFieldName = 'adminPasswordSecure'
    [string]$DateFieldName = 'adminPasswordLastSet'
    
    # --- Password Rotation Policy ---
    [int]$PwdMaxAgeDays = 30
    ```
7.  Click **Save**.

### Step 3: Create a Custom Device Group (Recommended)

To target only active workstations, it's best to create a dynamic group.

1.  Navigate to the main **Devices** page.
2.  Use the filter controls at the top to define your target group. For example:
    * **Type**: `Windows Desktop`, `Windows Laptop`
    * **Status**: `Up`
3.  Once the filters are applied, click **Save group**.
4.  Give the group a descriptive name (e.g., "Online Workstations") and click **Save**.

### Step 4: Schedule the Automation Task

1.  Navigate to **Administration** -> **Tasks**.
2.  Click **New Task**.
3.  Configure the task:
    * **Name**: Give it a descriptive name like "LAPS Password Rotation".
    * **Task Type**: Select **Run Script**.
    * **Script**: Choose the script you added in Step 2.
    * **Targets**: Select the custom group you created in Step 3 (e.g., "Online Workstations").
    * **Schedule**: Set your desired recurring schedule (e.g., Daily).
4.  Click **Save** to activate the scheduled task.

## How It Works

The script executes in the following order:

1.  **Pre-flight Checks**: The script first checks if it's running on a server OS. If it is, and `$AllowOnServers` is `$false`, it exits. It also initializes logging.
2.  **Built-in Admin Check**: Finds the local account with the SID ending in `-500` and, if it's enabled and safe to do so, disables it.
3.  **Managed Admin Check**: Ensures the managed admin account exists and is enabled, creating it if necessary.
4.  **Password Age Check**: Reads the last rotation date from the custom field and determines if a password change is needed.
5.  **Password Rotation**: If required, generates a new password, sets it on the local account, and updates the custom fields in NinjaOne.
