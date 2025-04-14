# Azure Security Lab Deployment Script
# This script automates the deployment of the Azure Security Lab infrastructure using Azure CLI and Bicep templates.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = "MalwareLab",
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "westus2",
    
    [Parameter(Mandatory = $false)]
    [string]$Prefix = "mallab",
    
    [Parameter(Mandatory = $false)]
    [string]$IpAddress,
    
    [Parameter(Mandatory = $false)]
    [switch]$ManualPassword,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDependencyCheck,

    [Parameter(Mandatory = $false)]
    [ValidateSet('MaxLoggingForDetectionDev', 'ProductionTuned')]
    [string]$LoggingProfile = 'MaxLoggingForDetectionDev' # Default to max logging
)

# Functions
function Write-LogInfo {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Green
}

function Write-LogWarning {
    param (
        [string]$Message
    )
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Write-LogError {
    param (
        [string]$Message
    )
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Check-Dependencies {
    Write-LogInfo "Checking for Azure CLI installation..."
    try {
        $azVersion = az --version
        if ($LASTEXITCODE -ne 0) {
            throw "Azure CLI not found or not working"
        }
        Write-LogInfo "Azure CLI is installed."
        return $true
    }
    catch {
        Write-LogError "Azure CLI not found. Please install it from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        return $false
    }
}

function Get-PublicIP {
    Write-LogInfo "Attempting to automatically detect public IP address..."
    try {
        $response = Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 10
        Write-LogInfo "Successfully detected public IP: $response"
        return $response
    }
    catch {
        Write-LogWarning "Could not automatically detect public IP address: $_"
        return $null
    }
}

function Check-AzureLogin {
    Write-LogInfo "Checking Azure login status..."
    $account = az account show | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Not logged in to Azure. Please run 'az login' first."
        return $false
    }
    
    Write-LogInfo "Logged in as: $($account.user.name)"
    Write-LogInfo "Subscription: $($account.name)"
    return $true
}

function Generate-StrongPassword {
    param (
        [int]$Length = 16
    )
    
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?".ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($Length)
    $rng.GetBytes($bytes)
    
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $charSet[$bytes[$i] % $charSet.Length]
    }
    
    # Ensure password contains at least one of each required character type
    $hasLower = $password -cmatch "[a-z]"
    $hasUpper = $password -cmatch "[A-Z]"
    $hasDigit = $password -cmatch "[0-9]"
    $hasSpecial = $password -cmatch "[^a-zA-Z0-9]"
    
    if (-not ($hasLower -and $hasUpper -and $hasDigit -and $hasSpecial)) {
        # If missing any character type, generate a new password
        return Generate-StrongPassword -Length $Length
    }
    
    return $password
}

# Main Deployment Function
function Deploy-AzureLab {
    # Setup path to infrastructure - More robust path detection
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        # If dot-sourced, try to get the path from invocation
        $scriptPath = $MyInvocation.MyCommand.Path
    }
    
    if (-not $scriptPath) {
        # Fallback to a hardcoded relative path from current directory
        Write-LogWarning "Unable to determine script path. Using current directory as base."
        $scriptDir = Get-Location
        $infrastructureDir = Join-Path (Split-Path -Parent $scriptDir) "infrastructure"
    } else {
        $scriptDir = Split-Path -Parent $scriptPath
        $infrastructureDir = Join-Path (Split-Path -Parent $scriptDir) "infrastructure"
    }
    
    $mainBicepFile = Join-Path $infrastructureDir "main.bicep"
    
    # Check if Bicep file exists
    if (-not (Test-Path $mainBicepFile)) {
        Write-LogError "Main Bicep file not found at expected location: $mainBicepFile"
        return $false
    }
    
    # --- Resource Group Handling --- 
    $targetResourceGroup = $ResourceGroup # Start with the user-provided name
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    
    Write-LogInfo "Checking resource group '$targetResourceGroup'..."
    $groupExists = az group exists --name $targetResourceGroup
    
    if ($groupExists -eq $true) {
        Write-LogInfo "Resource group '$targetResourceGroup' exists. Checking if it contains resources..."
        $resourcesInGroup = az resource list --resource-group $targetResourceGroup --output json | ConvertFrom-Json
        if ($resourcesInGroup.Count -gt 0) {
            $newRgName = "${targetResourceGroup}-${timestamp}"
            Write-LogWarning "Resource group '$targetResourceGroup' is not empty. Creating a new group: '$newRgName'"
            $targetResourceGroup = $newRgName
        } else {
            Write-LogInfo "Resource group '$targetResourceGroup' exists and is empty. Using existing group."
        }
    } else {
        Write-LogInfo "Resource group '$targetResourceGroup' does not exist. It will be created."
    }
    # --- End Resource Group Handling ---

    # Create or Verify the Target Resource Group
    Write-LogInfo "Ensuring resource group '$targetResourceGroup' exists in '$Location'..."
    $rgResult = az group create --name $targetResourceGroup --location $Location --output none
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Failed to create or verify resource group '$targetResourceGroup'."
        return $false
    }
    
    # Prepare Deployment Parameters
    $deploymentName = "$Prefix-deployment-$timestamp"
    Write-LogInfo "Starting Bicep deployment: $deploymentName in resource group '$targetResourceGroup' with Logging Profile: '$LoggingProfile'"
    
    # Execute Bicep Deployment
    Write-LogInfo "Executing Bicep deployment. This may take several minutes..."
    
    $escapedMainBicepFile = $mainBicepFile -replace '\\', '\\'
    
    # Build the deployment command, adding the loggingProfile parameter
    $deploymentCmd = "az deployment group create " +
                    "--resource-group `"$targetResourceGroup`" " +
                    "--name `"$deploymentName`" " +
                    "--template-file `"$escapedMainBicepFile`" " +
                    "--parameters namePrefix=`"$Prefix`" " +
                    "--parameters allowedSourceIpAddress=`"$IpAddress`" " +
                    "--parameters loggingProfile=`"$LoggingProfile`" " # Add logging profile parameter
    
    if ($ManualPassword) {
        Write-LogInfo "--- Manual Password Input ---"
        $adminUsername = Read-Host "Enter admin username for the VM"
        $adminPasswordSecure = Read-Host "Enter admin password for the VM" -AsSecureString
        $adminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPasswordSecure))
        
        $sqlAdminPasswordSecure = Read-Host "Enter SQL admin password for Synapse" -AsSecureString
        $sqlAdminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sqlAdminPasswordSecure))
        
        # Retrieve Key Vault Admin Object ID (current user)
        $keyVaultAdminObjectId = az ad signed-in-user show --query id -o tsv
        if ($LASTEXITCODE -ne 0 -or -not $keyVaultAdminObjectId) {
            Write-LogError "Failed to retrieve Azure AD Object ID for Key Vault admin. Please ensure you are logged in with 'az login'."
            return $false
        }
        
        $deploymentCmd += "--parameters adminUsername=`"$adminUsername`" " +
                        "--parameters adminPassword=`"$adminPassword`" " +
                        "--parameters sqlAdminPassword=`"$sqlAdminPassword`" " +
                        "--parameters keyVaultAdminObjectId=`"$keyVaultAdminObjectId`" "
        
        Write-LogInfo "--- End Manual Password Input ---"
    }
    else {
        # Auto-generate password - Bicep needs admin username and KV admin ID
        $adminUsername = "labadmin" # Define default admin username
        $adminPassword = Generate-StrongPassword # Generate strong password
        $sqlAdminPassword = Generate-StrongPassword # Generate strong password for SQL

        # Retrieve Key Vault Admin Object ID (current user)
        $keyVaultAdminObjectId = az ad signed-in-user show --query id -o tsv
        if ($LASTEXITCODE -ne 0 -or -not $keyVaultAdminObjectId) {
            Write-LogError "Failed to retrieve Azure AD Object ID for Key Vault admin. Please ensure you are logged in with 'az login'."
            return $false
        }
        
        $deploymentCmd += "--parameters adminUsername=`"$adminUsername`" " +
                        "--parameters adminPassword=`"$adminPassword`" " +
                        "--parameters sqlAdminPassword=`"$sqlAdminPassword`" " +
                        "--parameters keyVaultAdminObjectId=`"$keyVaultAdminObjectId`" "
        
        Write-LogInfo "Using auto-generated passwords (recommended). Passwords will be stored in Key Vault."
    }
    
    # Commented out to prevent logging secrets
    # Write-LogInfo "Command: $deploymentCmd"
    
    # Execute Bicep Deployment
    # Add --output json to get structured output from Azure CLI
    $deploymentResultJson = Invoke-Expression "$deploymentCmd --output json" 
    
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Bicep deployment command failed."
        # Attempt to log the raw output if possible
        Write-LogError "Raw output (may contain errors): $deploymentResultJson"
        return $false
    }
    
    Write-LogInfo "Bicep deployment command executed successfully."

    # Parse the JSON output
    try {
        $deploymentResult = $deploymentResultJson | ConvertFrom-Json
        if (-not $deploymentResult -or -not $deploymentResult.properties -or -not $deploymentResult.properties.outputs) {
            Write-LogError "Failed to parse deployment result or outputs missing."
            Write-LogError "Parsed Result: $deploymentResult"
            return $false
        }
    }
    catch {
        Write-LogError "Error parsing Bicep deployment JSON output: $_"
        Write-LogError "Raw JSON Output: $deploymentResultJson"
        return $false
    }
    
    # Parse Deployment Outputs
    Write-LogInfo "Retrieving deployment outputs..."
    try {
        $outputs = $deploymentResult.properties.outputs
        
        $vmName = $outputs.vmName.value
        $kvName = $outputs.keyVaultName.value
        $identityClientId = $outputs.vmManagedIdentityClientId.value
        $ehNamespace = $outputs.eventHubNamespaceName.value
        $adminUsernameOut = $outputs.adminUsername.value
        
        if (-not ($vmName -and $kvName -and $identityClientId -and $ehNamespace -and $adminUsernameOut)) {
            Write-LogError "Missing one or more expected outputs from deployment."
            Write-LogError "Outputs received: $outputs"
            return $false
        }
    }
    catch {
        Write-LogError "Error parsing deployment outputs: $_"
        return $false
    }
    
    # Retrieve VM Admin Password from Key Vault
    Write-LogInfo "Retrieving VM admin password from Key Vault '$kvName'..."
    $vmPassword = az keyvault secret show --vault-name $kvName --name "vm-admin-password" --query "value" -o tsv
    
    if ($LASTEXITCODE -ne 0) {
        Write-LogWarning "Failed to retrieve VM admin password from Key Vault."
        $vmPassword = "<Failed to retrieve - check Key Vault>"
    }
    
    # Retrieve VM Public IP Address (Assuming output named 'vmPublicIpAddress' from main.bicep)
    Write-LogInfo "Retrieving VM Public IP Address..."
    $vmPublicIp = $outputs.vmPublicIpAddress.value
    if (-not $vmPublicIp) {
        Write-LogWarning "Failed to retrieve VM Public IP address from deployment outputs."
        $vmPublicIp = "<Not Found>"
    }
    
    # Print Summary and Next Steps
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "         Deployment Successful!"
    Write-Host "----------------------------------------"
    Write-Host "Resource Group:  $targetResourceGroup" // Use targetResourceGroup
    Write-Host "Location:        $Location"
    Write-Host "VM Name:         $vmName"
    Write-Host "VM Public IP:    $vmPublicIp"
    Write-Host "Key Vault Name:  $kvName"
    Write-Host "EventHub NS:     $ehNamespace"
    Write-Host "VM Identity ID:  $identityClientId"
    Write-Host "VM Admin User:   $adminUsernameOut"
    Write-Host "VM Admin Pass:   $vmPassword"
    Write-Host "RDP Access:      Use Public IP ($vmPublicIp) from allowed source: $IpAddress"
    Write-Host "----------------------------------------"
    Write-Host "         Deployed Components Overview"
    Write-Host "----------------------------------------"
    Write-Host "*   Infrastructure:"
    Write-Host "    *   Virtual Machine: $vmName (Windows Server 2022) with Public IP: $vmPublicIp"
    Write-Host "    *   Networking: VNet, Subnets, NSG with RDP restricted to: $IpAddress"
    Write-Host "    *   Storage Account"
    Write-Host "    *   Log Analytics Workspace (for logging)"
    Write-Host "    *   Event Hubs Namespace: $ehNamespace (for high-volume telemetry)"
    Write-Host "    *   Key Vault: $kvName (for secrets)"
    Write-Host "    *   Managed Identity (for secure service communication)"
    Write-Host "    *   Synapse Workspace, Cosmos DB, Stream Analytics, Azure Functions"
    Write-Host ""
    Write-Host "*   Collection Agents:"
    Write-Host "    *   Azure Monitor Agent (AMA): Deployed on VM via Bicep (collects standard Windows logs and Sysmon)."
    Write-Host "    *   Data Collection Rules: Standard Microsoft-SecurityEvent, Sysmon, and Performance counters."
    Write-Host ""
    Write-Host "*   Detection & Analysis Functions:"
    Write-Host "    *   Azure Sentinel: Enabled on Log Analytics Workspace (SIEM/SOAR)."
    Write-Host "    *   Log Analytics Workspace: Central location for KQL queries."
    Write-Host "    *   Jupyter Notebook (`Azure_Security_Lab.ipynb`): For ML-based anomaly detection examples."
    Write-Host "----------------------------------------"
    Write-Host "            Next Steps"
    Write-Host "----------------------------------------"
    Write-Host "1. Connect to the VM via RDP:"
    Write-Host "   - Use Remote Desktop Connection to connect to IP: $vmPublicIp"
    Write-Host "   - Ensure your current IP ($IpAddress) is allowed by the NSG."
    Write-Host "   - Username: $adminUsernameOut"
    Write-Host "   - Password: $vmPassword"
    Write-Host ""
    Write-Host "2. Verify Log Collection:"
    Write-Host "   - In Azure Portal, navigate to your Log Analytics workspace."
    Write-Host "   - Go to 'Logs' and run a query like: 'SecurityEvent | take 10' to verify data is flowing."
    Write-Host "   - It may take 5-10 minutes for initial data to appear."
    Write-Host ""
    Write-Host "3. Configure Sentinel Analytics Rules:"
    Write-Host "   - Go to your Sentinel instance in Azure Portal."
    Write-Host "   - Navigate to 'Analytics' to create security detection rules."
    Write-Host ""
    Write-Host "4. (Optional) Configure Stream Analytics:"
    Write-Host "   - Set up Stream Analytics job to filter logs from Event Hubs to Log Analytics/ADLS."
    Write-Host "   - This can help reduce costs by filtering out unwanted events."
    Write-Host "----------------------------------------"
    
    return $true
}

# Main script execution
# Check for dependencies
if (-not $SkipDependencyCheck) {
    $depsOk = Check-Dependencies
    if (-not $depsOk) {
        exit 1
    }
}

# Check Azure login
$loginOk = Check-AzureLogin
if (-not $loginOk) {
    exit 1
}

# Determine IP address
if (-not $IpAddress) {
    $IpAddress = Get-PublicIP
    if (-not $IpAddress) {
        $IpAddress = "*"
        Write-LogWarning "IP detection failed. Falling back to allowing all IPs ('*'). For better security, consider using the -IpAddress parameter."
    }
}
elseif ($IpAddress -eq "*") {
    Write-LogWarning "Using '*' for IP address allows RDP access from any IP. This is not recommended for security."
}
else {
    Write-LogInfo "Using provided IP address for RDP restriction: $IpAddress"
}

# Deploy the lab
$deploymentSuccessful = Deploy-AzureLab
if ($deploymentSuccessful) {
    Write-LogInfo "Deployment script finished successfully."
    exit 0
}
else {
    Write-LogError "Deployment script failed."
    exit 1
} 