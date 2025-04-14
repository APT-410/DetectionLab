param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = "SecurityTestVMs",
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    
    [Parameter(Mandatory = $false)]
    [string]$DeploymentName = "TestVMDeployment",
    
    [Parameter(Mandatory = $false)]
    [string]$Prefix = "testvm",
    
    [Parameter(Mandatory = $false)]
    [switch]$ManualPassword = $false,
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsWorkspaceId
)

# Check if Azure CLI is installed
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI not found. Please install Azure CLI first."
    return
}

# Check if logged in to Azure
$loginStatus = az account show --query name -o tsv 2>$null
if (-not $loginStatus) {
    Write-Host "Not logged in to Azure. Please login."
    az login
}

# If Log Analytics workspace ID is not provided, try to find it
if (-not $LogAnalyticsWorkspaceId) {
    Write-Host "Log Analytics workspace ID not provided. Looking for existing workspace in resource group..."
    $workspaces = az monitor log-analytics workspace list --query "[].id" -o tsv
    
    if ($workspaces) {
        Write-Host "Found the following workspaces:"
        $i = 1
        $workspaceList = @()
        foreach ($workspace in $workspaces) {
            $name = $workspace.Split('/')[-1]
            $workspaceRg = ($workspace.Split('/') | Select-Object -Index 4)
            Write-Host "$i. $name (in $workspaceRg)"
            $workspaceList += $workspace
            $i++
        }
        
        $selection = Read-Host "Enter the number of the workspace to use, or press Enter to create a new resource group"
        if ($selection -and [int]$selection -le $workspaceList.Count) {
            $LogAnalyticsWorkspaceId = $workspaceList[[int]$selection - 1]
            Write-Host "Selected workspace: $LogAnalyticsWorkspaceId"
        }
    }
    
    if (-not $LogAnalyticsWorkspaceId) {
        Write-Error "No Log Analytics workspace ID provided or selected. Please deploy the main lab first or provide a workspace ID."
        return
    }
}

# Create resource group if it doesn't exist
Write-Host "Ensuring resource group '$ResourceGroup' exists in '$Location'..."
az group create --name $ResourceGroup --location $Location --output none

# Setup deployment parameters
$deploymentParams = @(
    "--name", $DeploymentName,
    "--resource-group", $ResourceGroup,
    "--template-file", "./bicep/main.bicep",
    "--parameters", "deploymentPrefix=$Prefix",
    "--parameters", "logAnalyticsWorkspaceId=$LogAnalyticsWorkspaceId"
)

if ($ManualPassword) {
    Write-Host "--- Manual Password Input ---"
    $adminUser = Read-Host "Enter admin username for the VM"
    $securePassword = Read-Host "Enter admin password for the VM" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $adminPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) # Clear from memory
    
    $deploymentParams += "--parameters"
    $deploymentParams += "passwordHandling=Manual"
    $deploymentParams += "--parameters" 
    $deploymentParams += "adminUsername=$adminUser"
    $deploymentParams += "--parameters"
    $deploymentParams += "adminPassword=$adminPass"
    Write-Host "--- End Manual Password Input ---"
} else {
    Write-Host "Using auto-generated passwords (recommended). Passwords will be stored in Key Vault."
    # Default admin username can be overridden here if desired
    $adminUser = "testadmin"
    $deploymentParams += "--parameters"
    $deploymentParams += "adminUsername=$adminUser"
}

# Execute Bicep Deployment
Write-Host "Deploying testing VM..."
$deploymentOutput = az deployment group create $deploymentParams | ConvertFrom-Json

if (-not $deploymentOutput) {
    Write-Error "Deployment failed."
    return
}

# Extract deployment outputs
$vmName = $deploymentOutput.properties.outputs.vmName.value
$keyVaultName = $deploymentOutput.properties.outputs.keyVaultName.value
$vmManagedIdentityClientId = $deploymentOutput.properties.outputs.vmManagedIdentityClientId.value

# Get admin password from Key Vault if auto-generated
if (-not $ManualPassword) {
    $adminPassword = az keyvault secret show --vault-name $keyVaultName --name vm-admin-password --query value -o tsv
    if (-not $adminPassword) {
        Write-Warning "Failed to retrieve VM admin password from Key Vault."
        $adminPassword = "<Failed to retrieve - check Key Vault>"
    }
}

# Print Summary and Next Steps
Write-Host "`n----------------------------------------"
Write-Host "         Deployment Successful!"
Write-Host "----------------------------------------"
Write-Host "Resource Group:  $ResourceGroup"
Write-Host "Location:        $Location"
Write-Host "VM Name:         $vmName"
Write-Host "Key Vault Name:  $keyVaultName"
Write-Host "VM Identity ID:  $vmManagedIdentityClientId"
Write-Host "VM Admin User:   $adminUser"
Write-Host "VM Admin Pass:   $adminPassword"
Write-Host "----------------------------------------"

# Connect to VM instructions
Write-Host "`nTo connect to the testing VM:"
Write-Host "1. Use RDP to connect to the VM's public IP or FQDN"
Write-Host "2. Username: $adminUser"
Write-Host "3. Password: $adminPassword"

# Return to original directory
Write-Host "`nDeployment completed successfully."