# Azure Security Lab Deployment Wrapper Script
# This script serves as a simple wrapper for the main deployment script.

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
    [string]$ManualPassword,

    [Parameter(Mandatory = $false)]
    [ValidateSet('MaxLoggingForDetectionDev', 'ProductionTuned')]
    [string]$LoggingProfile # No default here, let Deploy-Lab.ps1 handle it
)

# Build parameter set for main script
$params = @{
    ResourceGroup = $ResourceGroup
    Location = $Location
    Prefix = $Prefix
}

# Only add IpAddress if provided
if ($IpAddress) {
    $params.Add("IpAddress", $IpAddress)
}

# Add ManualPassword switch if specified
if ($ManualPassword) {
    $params.Add("ManualPassword", $true)
}

# Add LoggingProfile if specified
if ($PSBoundParameters.ContainsKey('LoggingProfile')) {
    $params.Add("LoggingProfile", $LoggingProfile)
}

# Display the command that will be executed
Write-Host "Executing deployment script with parameters:" -ForegroundColor Green
foreach ($key in $params.Keys) {
    if ($key -eq "ManualPassword") {
        Write-Host "  -$key" -ForegroundColor Green
    } else {
        Write-Host "  -$key $($params[$key])" -ForegroundColor Green
    }
}

# Execute the main deployment script
& "$PSScriptRoot\deployment\Deploy-Lab.ps1" @params 