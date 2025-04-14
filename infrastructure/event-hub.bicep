@description('Prefix for resource names')
param namePrefix string = 'secLab'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Event Hubs Namespace SKU')
@allowed([
  'Basic'
  'Standard'
  'Premium'
])
param namespaceSku string = 'Standard'

@description('Number of partitions for the Event Hub')
@minValue(1)
@maxValue(32) // Standard tier max, Premium goes higher
param partitionCount int = 4

@description('Enable Auto-Inflate for Standard SKU, or use scaling for Premium')
param enableAutoInflate bool = (namespaceSku == 'Standard')

@description('Maximum Throughput Units for Auto-Inflate (Standard SKU)')
param maxThroughputUnits int = (namespaceSku == 'Standard') ? 10 : 0 // Example default

@description('Name for the specific Event Hub instance')
param eventHubName string = 'endpoint-logs'

// Variables
var eventHubNamespaceName = '${namePrefix}ehns${uniqueString(resourceGroup().id)}'

resource eventHubNamespace 'Microsoft.EventHub/namespaces@2023-01-01-preview' = {
  name: eventHubNamespaceName
  location: location
  sku: {
    name: namespaceSku
    tier: namespaceSku
    capacity: (namespaceSku == 'Premium') ? 1 : null // Base capacity for Premium, Standard uses TUs
  }
  properties: {
    isAutoInflateEnabled: enableAutoInflate
    maximumThroughputUnits: enableAutoInflate ? maxThroughputUnits : 0
    zoneRedundant: (namespaceSku == 'Premium') // Zone redundancy only for Premium
    disableLocalAuth: false // Consider setting to true and using AAD auth
  }
}

resource eventHub 'Microsoft.EventHub/namespaces/eventhubs@2023-01-01-preview' = {
  parent: eventHubNamespace
  name: eventHubName
  properties: {
    partitionCount: partitionCount
    messageRetentionInDays: (namespaceSku == 'Premium') ? 7 : 1 // Example retention
    // partitionIds: [] // Partitions are auto-created
  }
}

// Authorization rule to get connection string (consider Managed Identity for prod)
// resource authRule 'Microsoft.EventHub/namespaces/authorizationRules@2023-01-01-preview' = {
//   parent: eventHubNamespace
//   name: 'RootManageSharedAccessKey' // Using built-in, consider creating a specific one
//   properties: {
//     rights: [
//       'Listen'
//       'Send'
//       'Manage'
//     ]
//   }
// }

output namespaceName string = eventHubNamespace.name
output namespaceId string = eventHubNamespace.id
output eventHubName string = eventHub.name
// output primaryConnectionString string = listKeys(authRule.id, eventHubNamespace.apiVersion).primaryConnectionString // Removed output for security
