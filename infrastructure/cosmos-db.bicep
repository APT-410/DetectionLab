@description('Cosmos DB account name')
param cosmosDbAccountName string

@description('Location for the Cosmos DB account')
param location string = resourceGroup().location

@description('The primary region for the Cosmos DB account')
param primaryRegion string = location

@description('The secondary region for the Cosmos DB account')
param secondaryRegion string = ''

@description('ID of the managed identity to assign to the Cosmos DB account')
param managedIdentityId string

@description('The Principal ID of the managed identity to grant permissions')
param centralManagedIdentityPrincipalId string

@allowed([
  'Eventual'
  'ConsistentPrefix'
  'Session'
  'BoundedStaleness'
  'Strong'
])
@description('The default consistency level for the Cosmos DB account')
param defaultConsistencyLevel string = 'Session'

@minValue(10)
@maxValue(1000000)
@description('Maximum lag time (in seconds) for BoundedStaleness consistency')
param maxStalenessPrefix int = 100000

@minValue(5)
@maxValue(86400)
@description('Maximum staleness bound (in seconds) for BoundedStaleness consistency')
param maxIntervalInSeconds int = 300

@allowed([
  'EnableServerless'
  'EnableAutoscale'
  'EnableStandard'
])
@description('The capacity mode for the Cosmos DB account')
param capacityMode string = 'EnableAutoscale'

@description('Max throughput for the security-alerts container')
param alertsMaxThroughput int = 1000

@description('Max throughput for the security-events container')
param eventsMaxThroughput int = 5000

// Variables
var consistencyPolicy = {
  Eventual: {
    defaultConsistencyLevel: 'Eventual'
  }
  ConsistentPrefix: {
    defaultConsistencyLevel: 'ConsistentPrefix'
  }
  Session: {
    defaultConsistencyLevel: 'Session'
  }
  BoundedStaleness: {
    defaultConsistencyLevel: 'BoundedStaleness'
    maxStalenessPrefix: maxStalenessPrefix
    maxIntervalInSeconds: maxIntervalInSeconds
  }
  Strong: {
    defaultConsistencyLevel: 'Strong'
  }
}

var locations = !empty(secondaryRegion) ? [
  {
    locationName: primaryRegion
    failoverPriority: 0
    isZoneRedundant: false
  }
  {
    locationName: secondaryRegion
    failoverPriority: 1
    isZoneRedundant: false
  }
] : [
  {
    locationName: primaryRegion
    failoverPriority: 0
    isZoneRedundant: false
  }
]

var actualLocations = !empty(secondaryRegion) ? union(locations, [ { locationName: secondaryRegion, failoverPriority: 1 } ]) : locations

var securityDbName = 'security-db'
var eventsContainerName = 'events'
var alertsContainerName = 'alerts'
var behaviorContainerName = 'behaviorProfiles'

// Cosmos DB Account
resource cosmosDbAccount 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {
  name: cosmosDbAccountName
  location: location
  kind: 'GlobalDocumentDB'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    consistencyPolicy: consistencyPolicy[defaultConsistencyLevel]
    locations: actualLocations
    databaseAccountOfferType: 'Standard'
    enableAutomaticFailover: !empty(secondaryRegion)
    capabilities: capacityMode == 'EnableServerless' ? [
      {
        name: 'EnableServerless'
      }
    ] : []
    enableFreeTier: false
    enableMultipleWriteLocations: false
    enableAnalyticalStorage: true  // Enable analytical store for Synapse Link
    analyticalStorageConfiguration: {
      schemaType: 'WellDefined'
    }
    networkAclBypass: 'AzureServices'
  }
}

// Security Database
resource securityDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2023-04-15' = {
  name: securityDbName
  parent: cosmosDbAccount
  properties: {
    resource: {
      id: securityDbName
    }
    options: {}
  }
}

// Security Alerts Container
resource alertsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: alertsContainerName
  parent: securityDatabase
  properties: {
    resource: {
      id: 'security-alerts'
      partitionKey: {
        paths: [
          '/alertId'
        ]
        kind: 'Hash'
      }
      indexingPolicy: {
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
        compositeIndexes: [
          [
            {
              path: '/timeGenerated'
              order: 'descending'
            }
            {
              path: '/severity'
              order: 'descending'
            }
          ]
          [
            {
              path: '/severity'
              order: 'descending'
            }
            {
              path: '/hostname'
              order: 'ascending'
            }
          ]
        ]
      }
      defaultTtl: 7776000 // 90 days in seconds
    }
    options: capacityMode == 'EnableAutoscale' ? {
      autoscaleSettings: {
        maxThroughput: alertsMaxThroughput
      }
    } : {}
  }
}

// Security Events Container
resource eventsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: eventsContainerName
  parent: securityDatabase
  properties: {
    resource: {
      id: 'security-events'
      partitionKey: {
        paths: [
          '/id'
        ]
        kind: 'Hash'
      }
      indexingPolicy: {
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
        compositeIndexes: [
          [
            {
              path: '/metadata/timestamp'
              order: 'descending'
            }
            {
              path: '/metadata/hostname'
              order: 'ascending'
            }
          ]
          [
            {
              path: '/metadata/event_type'
              order: 'ascending'
            }
            {
              path: '/metadata/timestamp'
              order: 'descending'
            }
          ]
        ]
      }
      defaultTtl: 2592000 // 30 days in seconds
    }
    options: capacityMode == 'EnableAutoscale' ? {
      autoscaleSettings: {
        maxThroughput: eventsMaxThroughput
      }
    } : {}
  }
}

// Behavioral Analytics Container for ML results
resource behaviorContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: behaviorContainerName
  parent: securityDatabase
  properties: {
    resource: {
      id: 'behavior-analytics'
      partitionKey: {
        paths: [
          '/entityId'
        ]
        kind: 'Hash'
      }
      indexingPolicy: {
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
        compositeIndexes: [
          [
            {
              path: '/timestamp'
              order: 'descending'
            }
            {
              path: '/entityType'
              order: 'ascending'
            }
          ]
          [
            {
              path: '/anomalyScore'
              order: 'descending'
            }
            {
              path: '/timestamp'
              order: 'descending'
            }
          ]
        ]
      }
      defaultTtl: 7776000 // 90 days in seconds
    }
    options: capacityMode == 'EnableAutoscale' ? {
      autoscaleSettings: {
        maxThroughput: alertsMaxThroughput
      }
    } : {}
  }
}

// Setup Cosmos DB Link with Synapse (if needed)
resource synapseLink 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/analyticalstores@2023-04-15' = {
  parent: eventsContainer
  name: 'default'
  properties: {
    schema: {
      type: 'FullFidelity'
    }
    autoPauseAndScaleSettings: {
      autoPause: true
      idleTimeInMinutes: 30
      minRu: 100
    }
  }
}

// Define the built-in Cosmos DB Data Contributor Role
resource cosmosDbDataContributorRole 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription() // Scope for built-in role definition
  name: '5bd9cd88-fe45-4216-938b-f97437e15450' // Role Definition ID for Cosmos DB Data Contributor
}

// Assign the role to the central managed identity
resource managedIdentityCosmosDbRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: cosmosDbAccount // Assign role at the Cosmos DB account level
  name: guid(cosmosDbAccount.id, centralManagedIdentityPrincipalId, cosmosDbDataContributorRole.id)
  properties: {
    roleDefinitionId: cosmosDbDataContributorRole.id
    principalId: centralManagedIdentityPrincipalId // Use the Principal ID passed as parameter
    principalType: 'ServicePrincipal'
  }
  dependsOn: [ // Ensure account exists before assigning role
    cosmosDbAccount
  ]
}

// Outputs
output cosmosDbAccountName string = cosmosDbAccount.name
output cosmosDbAccountId string = cosmosDbAccount.id
output securityDbName string = securityDatabase.name
output alertsContainerName string = alertsContainer.name
output eventsContainerName string = eventsContainer.name
output behaviorContainerName string = behaviorContainer.name
output cosmosDbEndpoint string = cosmosDbAccount.properties.documentEndpoint
output cosmosDbAccountResourceId string = cosmosDbAccount.id
