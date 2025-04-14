targetScope = 'resourceGroup'

@description('Prefix used for all resource names')
param namePrefix string = 'seclab'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Admin username for VM and Synapse SQL')
param adminUsername string

@description('Admin password for VM and Synapse SQL. Store in Key Vault for production.')
@secure()
param adminPassword string

@description('Object ID of the user/group to grant initial Key Vault admin access')
param keyVaultAdminObjectId string

@description('Your public IP address or CIDR range for NSG rule to allow Bastion/RDP access')
param allowedSourceIpAddress string

@description('Logging profile to use: MaxLoggingForDetectionDev (verbose) or ProductionTuned (balanced)')
@allowed([ 'MaxLoggingForDetectionDev', 'ProductionTuned' ])
param loggingProfile string = 'MaxLoggingForDetectionDev'

// Instantiate Modules

module network './networking.bicep' = {
  name: '${deployment().name}-network' // Add deployment name for uniqueness
  params: {
    namePrefix: namePrefix
    location: location
    allowedSourceIpAddress: allowedSourceIpAddress
  }
}

module kv './key-vault.bicep' = {
  name: '${deployment().name}-kv'
  params: {
    namePrefix: namePrefix
    location: location
    keyVaultAdminObjectId: keyVaultAdminObjectId
  }
}

// If storing VM password in KV (recommended)
// resource vmPasswordSecret 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
//   parent: kv // Reference the module output
//   name: 'vmAdminPassword'
//   properties: {
//     value: adminPassword
//   }
// }

module logAnalytics './log-analytics.bicep' = {
  name: '${deployment().name}-la'
  params: {
    namePrefix: namePrefix
    location: location
    enableSentinel: true
  }
}

// Event Hub module remains for potential PaaS log ingestion or future use
module eventHub './event-hub.bicep' = {
  name: '${deployment().name}-eh'
  params: {
    namePrefix: namePrefix
    location: location
  }
}

module adls './storage-adls.bicep' = {
  name: '${deployment().name}-adls'
  params: {
    namePrefix: namePrefix
    location: location
    rawLogsContainerName: 'log-analytics-export'
    processedDataContainerName: 'processed-data'
    synapseDefaultContainerName: 'synapse'
    // storageSku: 'Standard_LRS' // Example if you needed to override default
  }
}

module synapse './synapse.bicep' = {
  name: '${deployment().name}-syn'
  params: {
    namePrefix: namePrefix
    location: location
    storageAccountName: adls.outputs.storageAccountName
    storageContainerName: 'synapse'
    sqlAdminLogin: adminUsername
    sqlAdminPassword: adminPassword
  }
  dependsOn: [
    adls
  ]
}

module vm './vm-windows.bicep' = {
  name: '${deployment().name}-vm'
  params: {
    namePrefix: namePrefix
    location: location
    adminUsername: adminUsername
    adminPassword: adminPassword 
    subnetId: network.outputs.defaultSubnetId
    keyVaultName: kv.outputs.keyVaultName 
  }
  dependsOn: [
    network, kv
  ]
}

// Data Collection Endpoint (Common for both DCR profiles)
// Moved DCE creation here from the old data-collection.bicep
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' = {
  name: '${namePrefix}-dce-${uniqueString(resourceGroup().id)}' // Ensure unique name
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// Conditionally deploy DCR based on loggingProfile
module dcrMaxLogging './dcr-max-logging-dev.bicep' = if (loggingProfile == 'MaxLoggingForDetectionDev') {
  name: '${deployment().name}-dcr-maxdev'
  params: {
    location: location
    workspaceId: logAnalytics.outputs.workspaceId
    vmId: vm.outputs.vmId
    managedIdentityId: vm.outputs.vmSystemAssignedPrincipalId // Assuming VM uses System Assigned MI
    dceId: dce.id
  }
  dependsOn: [
    vm, dce, logAnalytics // Ensure dependencies are met
  ]
}

module dcrProduction './dcr-production-tuned.bicep' = if (loggingProfile == 'ProductionTuned') {
  name: '${deployment().name}-dcr-prod'
  params: {
    location: location
    workspaceId: logAnalytics.outputs.workspaceId
    vmId: vm.outputs.vmId
    managedIdentityId: vm.outputs.vmSystemAssignedPrincipalId // Assuming VM uses System Assigned MI
    dceId: dce.id
  }
  dependsOn: [
    vm, dce, logAnalytics // Ensure dependencies are met
  ]
}

// --- Post-Deployment Steps (Manual or Scripted) ---
// 1. Assign Synapse Managed Identity Role (if role assignment in module fails due to permissions):
//    - 'Storage Blob Data Contributor' on ADLS Storage Account (use Principal ID outputted by Synapse module)
// 2. Deploy AMA via Policy to the VM/VMSS & assign DCR (sending DIRECTLY to Log Analytics)
// 3. Configure Log Analytics Data Export:
//    - Set up Data Export rules in the Log Analytics workspace to continuously export necessary tables (e.g., SecurityEvent, Syslog, Perf) to the ADLS Storage Account (e.g., into the 'log-analytics-export' container).
// 4. (Optional) Configure Diagnostic Settings for PaaS resources to send logs to Log Analytics or Event Hubs.

// --- Outputs --- (Expose key resource names/IDs/Endpoints)

output rgName string = resourceGroup().name
output location string = location
output eventHubNamespace string = eventHub.outputs.namespaceName // Keep for potential PaaS use
output logAnalyticsWorkspace string = logAnalytics.outputs.workspaceName
output logAnalyticsWorkspaceId string = logAnalytics.outputs.workspaceId
output adlsAccountName string = adls.outputs.storageAccountName
output adlsDfsEndpoint string = adls.outputs.storageEndpoint
output synapseWorkspaceName string = synapse.outputs.synapseWorkspaceName
output synapseDevEndpoint string = synapse.outputs.synapseDevEndpoint
output vmName string = vm.outputs.vmName
// Removed streamAnalyticsJobName output
output keyVaultName string = kv.outputs.keyVaultName
output vmPublicIpAddress string = vm.outputs.publicIpAddress // Added output for VM Public IP
output deployedDcrId string = (loggingProfile == 'MaxLoggingForDetectionDev') ? dcrMaxLogging.outputs.dataCollectionRuleId : dcrProduction.outputs.dataCollectionRuleId
