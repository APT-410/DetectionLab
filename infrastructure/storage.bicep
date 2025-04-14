@description('Name of the storage account')
param storageAccountName string

@description('Location for all resources')
param location string = resourceGroup().location

@description('Storage account SKU')
param storageAccountSku string = 'Standard_LRS'

@description('ID of the managed identity to use for storage access')
param managedIdentityId string

// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: storageAccountSku
  }
  properties: {
    allowBlobPublicAccess: false
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
        queue: {
          enabled: true
        }
        table: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Blob Services
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2022-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

// Create containers for security data
resource securityLogsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-05-01' = {
  parent: blobService
  name: 'security-logs'
  properties: {
    publicAccess: 'None'
  }
}

resource malwareAnalysisContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-05-01' = {
  parent: blobService
  name: 'malware-analysis'
  properties: {
    publicAccess: 'None'
  }
}

resource mlDataContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-05-01' = {
  parent: blobService
  name: 'ml-data'
  properties: {
    publicAccess: 'None'
  }
}

// Create synapse container
resource synapsefsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-05-01' = {
  parent: blobService
  name: 'synapsefs'
  properties: {
    publicAccess: 'None'
  }
}

// RBAC role assignment for managed identity - Storage Blob Data Contributor role
resource storageContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' // Storage Blob Data Contributor role ID
}

resource storageContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: storageAccount
  name: guid(storageAccount.id, managedIdentityId, storageContributorRoleDefinition.id)
  properties: {
    roleDefinitionId: storageContributorRoleDefinition.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// RBAC role assignment for managed identity - Storage Account Contributor role
resource storageAccountContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: '17d1049b-9a84-46fb-8f53-869881c3d3ab' // Storage Account Contributor role ID
}

resource storageAccountContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: storageAccount
  name: guid(storageAccount.id, managedIdentityId, storageAccountContributorRoleDefinition.id)
  properties: {
    roleDefinitionId: storageAccountContributorRoleDefinition.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output storageAccountName string = storageAccount.name
output storageAccountId string = storageAccount.id
output securityLogsContainerName string = securityLogsContainer.name
output malwareAnalysisContainerName string = malwareAnalysisContainer.name
output mlDataContainerName string = mlDataContainer.name
output synapsefsContainerName string = synapsefsContainer.name
