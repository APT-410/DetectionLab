@description('Prefix for resource names')
param namePrefix string // Provided by main.bicep

@description('Location for all resources')
param location string // Provided by main.bicep

@description('Name of the ADLS Gen2 storage account to link')
param storageAccountName string // Provided by main.bicep

@description('Filesystem (container) name in ADLS Gen2 for Synapse default storage')
param storageContainerName string = 'synapse' // Default, can be overridden by main.bicep

@description('SQL Administrator login username for Synapse SQL pool')
param sqlAdminLogin string // Provided by main.bicep

@description('SQL Administrator login password')
@secure()
param sqlAdminPassword string // Provided by main.bicep

@description('Number of nodes for the default Spark pool')
@minValue(1)
@maxValue(200) // Example limits, check latest docs
param sparkNodeCount int = 3 // Start small

@description('Size of the nodes for the default Spark pool')
@allowed([
  'Small'
  'Medium'
  'Large'
  'XLarge'
  'XXLarge'
])
param sparkNodeSize string = 'Small'

@description('Spark version for the default pool')
param sparkVersion string = '3.3' // Or newer supported version

// Variables
var synapseWorkspaceName_var = '${namePrefix}syn${uniqueString(resourceGroup().id)}' // Use _var suffix to avoid conflict
var defaultSparkPoolName = 'defaultSparkPool'

// Need storage account resource ID
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

// Create the dedicated container for Synapse default filesystem
// This assumes main.bicep provides the desired container name (e.g., 'synapse')
// NOTE: Container creation is now handled in storage-adls.bicep.
// We just need to reference the storage account here for role assignment and linking.

// Deploy Synapse workspace with system-assigned managed identity
resource synapseWorkspace 'Microsoft.Synapse/workspaces@2021-06-01' = {
  name: synapseWorkspaceName_var
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    defaultDataLakeStorage: {
      accountUrl: storageAccount.properties.primaryEndpoints.dfs
      filesystem: storageContainerName
    }
    sqlAdministratorLogin: sqlAdminLogin
    sqlAdministratorLoginPassword: sqlAdminPassword
    managedVirtualNetwork: 'default' // Enable managed VNet for security
    publicNetworkAccess: 'Enabled' // Consider 'Disabled' and use Private Endpoints
    // managedResourceGroupName: // Auto-generated if not specified
  }
  dependsOn: [
    storageAccount // Synapse depends on the storage account existing
  ]
}

// Assign Synapse Workspace Managed Identity the 'Storage Blob Data Contributor' role on the Storage Account
// Note: This requires the deploying principal to have Owner rights or equivalent. Can be done post-deployment.
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' // Built-in Role Definition ID

resource synapseMiStorageAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storageAccount
  name: guid(synapseWorkspace.id, storageAccount.id, storageBlobDataContributorRoleId)
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: synapseWorkspace.identity.principalId // Use the System Assigned Identity principalId
    principalType: 'ServicePrincipal'
  }
}

// Create a default Apache Spark pool
resource defaultSparkPool 'Microsoft.Synapse/workspaces/bigDataPools@2021-06-01' = {
  parent: synapseWorkspace
  name: defaultSparkPoolName // Use the variable defined earlier
  location: location
  properties: {
    autoScale: {
      enabled: true
      minNodeCount: sparkNodeCount
      maxNodeCount: sparkNodeCount + 2 // Example auto-scale range
    }
    autoPause: {
      enabled: true
      delayInMinutes: 15
    }
    nodeSizeFamily: 'MemoryOptimized'
    nodeSize: sparkNodeSize
    sparkVersion: sparkVersion
    // libraryRequirements: {} // Add libraries here if needed globally
  }
}

// Outputs
output synapseWorkspaceName string = synapseWorkspace.name
output synapseWorkspaceId string = synapseWorkspace.id
output synapseSparkPoolName string = defaultSparkPool.name // Output the name of the created pool
output synapseServerlessSqlEndpoint string = synapseWorkspace.properties.connectivityEndpoints.sql
output synapseDevEndpoint string = synapseWorkspace.properties.connectivityEndpoints.dev
output synapseSystemAssignedPrincipalId string = synapseWorkspace.identity.principalId
