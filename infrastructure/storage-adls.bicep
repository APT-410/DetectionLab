@description('Location for all resources')
param location string = resourceGroup().location

@description('Prefix for all resource names')
param namePrefix string = 'seclab'

@description('Storage account SKU')
param storageSku string = 'Standard_LRS'

@description('Enable Hierarchical Namespace for Data Lake functionality')
param enableHierarchicalNamespace bool = true

@description('Name for the container to store exported Log Analytics data')
param rawLogsContainerName string = 'log-analytics-export'

@description('Name for the container to store processed data')
param processedDataContainerName string = 'processed-data'

@description('Name for the default container used by Synapse')
param synapseDefaultContainerName string = 'synapse'

// Variables
var storageAccountName = '${namePrefix}adls${uniqueString(resourceGroup().id)}'

// Storage Account for ADLS Gen2
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: storageSku
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    isHnsEnabled: enableHierarchicalNamespace
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
}

// Define the default blob service (required parent for containers)
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default' // Must be 'default'
  properties: {
    // Add blob service properties if needed, e.g., CORS, delete retention
  }
}

// Define containers nested under the blobService resource
resource rawLogsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService // Reference the blobService resource
  name: rawLogsContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource processedDataContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService // Reference the blobService resource
  name: processedDataContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource synapseContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService // Reference the blobService resource
  name: synapseDefaultContainerName
  properties: {
    publicAccess: 'None'
  }
}

// Outputs
output storageAccountName string = storageAccount.name
output storageAccountId string = storageAccount.id
output storageEndpoint string = storageAccount.properties.primaryEndpoints.dfs 
