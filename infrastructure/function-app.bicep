@description('Name for the Azure Function App for security detections')
param functionAppName string

@description('Location for all resources')
param location string

@description('Storage Account name for function app')
param storageAccountName string

@description('Event Hub namespace name')
param eventHubNamespaceName string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

@description('ID of the managed identity to use')
param managedIdentityId string

@description('Python runtime version for the function app')
param pythonVersion string = '3.9'

// Get reference to the storage account
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' existing = {
  name: storageAccountName
}

// Get reference to Event Hub namespace
resource eventHubNamespace 'Microsoft.EventHub/namespaces@2022-01-01-preview' existing = {
  name: eventHubNamespaceName
}

// Create App Service Plan - Consumption plan for cost efficiency
resource appServicePlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: '${functionAppName}-plan'
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true // Required for Linux
  }
}

// Create Function App with Python runtime
resource functionApp 'Microsoft.Web/sites@2021-03-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'Python|${pythonVersion}'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storageAccount.id, storageAccount.apiVersion).keys[0].value}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(appInsights.id, appInsights.apiVersion).InstrumentationKey
        }
        {
          name: 'MANAGED_IDENTITY_CLIENT_ID'
          value: reference(managedIdentityId, '2018-11-30').clientId
        }
        {
          name: 'EVENT_HUB_NAMESPACE'
          value: eventHubNamespace.name
        }
        {
          name: 'EVENT_HUB_NAME_SECURITY'
          value: 'security-logs'
        }
        {
          name: 'EVENT_HUB_NAME_PROCESS'
          value: 'process-events'
        }
        {
          name: 'EVENT_HUB_NAME_NETWORK'
          value: 'network-events'
        }
        {
          name: 'WORKSPACE_ID'
          value: logAnalyticsWorkspaceId
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
    }
    httpsOnly: true
  }
}

// Application Insights for function monitoring
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${functionAppName}-insights'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
  }
}

// Create EventHub trigger function
// Role assignment for Function App to read from Event Hub
resource eventHubDataReceiverRole 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde' // EventHub Data Receiver role ID
}

resource eventHubRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: eventHubNamespace
  name: guid(eventHubNamespace.id, managedIdentityId, eventHubDataReceiverRole.id, 'function')
  properties: {
    roleDefinitionId: eventHubDataReceiverRole.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// Role assignment for Function App to write to Log Analytics
resource logAnalyticsContributorRole 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: '92aaf0da-9dab-42b6-94a3-d43ce8d16293' // Log Analytics Contributor role ID
}

resource logAnalyticsRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: resourceGroup()
  name: guid(resourceGroup().id, managedIdentityId, logAnalyticsContributorRole.id, 'function')
  properties: {
    roleDefinitionId: logAnalyticsContributorRole.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// Deploy sample function code for security detection
resource functionAppZipDeploy 'Microsoft.Web/sites/extensions@2021-02-01' = {
  parent: functionApp
  name: 'MSDeploy'
  properties: {
    // Using ZIP deployment with code from local repository
    // The deployment script will handle the actual deployment later
    packageUri: '' // Will be managed through local deployment
  }
  dependsOn: [
    eventHubRoleAssignment
    logAnalyticsRoleAssignment
  ]
}

// Outputs
output functionAppName string = functionApp.name
output functionAppDefaultHostname string = functionApp.properties.defaultHostName
