@description('Prefix for resource names')
param namePrefix string = 'secLab'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics Workspace SKU')
@allowed([
  'PerGB2018'
  'CapacityReservation' // Used with commitment tiers
  'Standalone' // Older, generally avoid
])
param workspaceSku string = 'PerGB2018' // Default to Pay-As-You-Go

@description('Data retention in days for the Log Analytics workspace')
@minValue(30)
@maxValue(730) // 2 years max retention, longer needs ADX
param retentionInDays int = 90 // Default to 90 days

@description('Whether to enable Microsoft Sentinel on this workspace.')
param enableSentinel bool = true

// Variables
var logAnalyticsWorkspaceName = '${namePrefix}la${uniqueString(resourceGroup().id)}'

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: workspaceSku
    }
    retentionInDays: retentionInDays
    // Features like publicNetworkAccessForIngestion/Query can be added for network hardening
  }
}

// Enable Sentinel on the Log Analytics Workspace
resource sentinelOnboarding 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (enableSentinel) {
  name: 'SecurityInsights(${logAnalyticsWorkspace.name})' // Sentinel solution name format
  location: location
  plan: {
    name: 'SecurityInsights(${logAnalyticsWorkspace.name})'
    publisher: 'Microsoft'
    promotionCode: ''
    product: 'OMSGallery/SecurityInsights'
  }
  properties: {
    workspaceResourceId: logAnalyticsWorkspace.id
  }
  dependsOn: [
    logAnalyticsWorkspace
  ]
}

output workspaceName string = logAnalyticsWorkspace.name
output workspaceId string = logAnalyticsWorkspace.id
output workspaceResourceId string = logAnalyticsWorkspace.id // Often used interchangeably
