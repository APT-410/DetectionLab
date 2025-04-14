@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics Workspace resource ID')
param workspaceId string

@description('VM Resource ID')
param vmId string

@description('ID of the managed identity to use for data collection')
param managedIdentityId string

// Reference to the existing VM
resource existingVm 'Microsoft.Compute/virtualMachines@2022-03-01' existing = {
  name: last(split(vmId, '/'))
}

// Create Azure Monitor Agent extension for Windows VM
resource azureMonitorAgentForWindows 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' = {
  parent: existingVm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// Create Data Collection Endpoint
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' = {
  name: '${existingVm.name}-dce'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// Create Data Collection Rule for Windows Security Events (Azure Security Pack)
resource securityEventsDcr 'Microsoft.Insights/dataCollectionRules@2021-09-01-preview' = {
  name: 'security-events-dcr'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    dataCollectionEndpointId: dce.id
    description: 'Data collection rule for Windows security events (Azure Security Pack)'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'security-events'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: [
            'Security!*[System[(EventID=4624 or EventID=4625)]]' // Logon/logoff events
            'Security!*[System[(EventID=4688)]]' // Process creation
            'Security!*[System[(EventID=4657 or EventID=4663)]]' // Registry and file access
            'Security!*[System[(EventID=5156 or EventID=5157)]]' // Network connections
            'Security!*[System[(EventID=4698 or EventID=4702)]]' // Scheduled task creation
            'Security!*[System[(EventID between 4700 and 4800)]]' // Other security events
          ]
        }
      ]
      performanceCounters: [
        {
          name: 'system-performance'
          streams: [
            'Microsoft-Perf'
          ]
          samplingFrequencyInSeconds: 60
          counterSpecifiers: [
            '\\Processor(_Total)\\% Processor Time'
            '\\Memory\\Available Bytes'
            '\\Network Interface(*)\\Bytes Received/sec'
            '\\Network Interface(*)\\Bytes Sent/sec'
            '\\Process(*)\\% Processor Time'
            '\\Process(*)\\Working Set'
          ]
        }
      ]
      extensions: [
        {
          name: 'azsecpack-windows-events'
          extensionName: 'SecurityEventCollector' 
          streams: [
            'Microsoft-WindowsEvent'
          ]
          extensionSettings: {
            windowsEventLogs: [
              {
                name: 'application-events'
                eventName: 'Application'
                eventLevel: 'Warning'
                recordNumber: 100
              }
              {
                name: 'system-events'
                eventName: 'System'
                eventLevel: 'Warning'
                recordNumber: 100
              }
              {
                name: 'security-auditing'
                eventName: 'Security'
                eventLevel: 'Warning'
                recordNumber: 100
                keywords: 9007199254740992
              }
            ]
          }
        }
        {
          name: 'azsecpack-sysmon'
          extensionName: 'SysmonDataCollector'
          streams: [
            'Microsoft-WindowsEvent'
          ]
          extensionSettings: {
            windowsEventLogs: [
              {
                name: 'microsoft-windows-sysmon-operational'
                eventName: 'Microsoft-Windows-Sysmon/Operational'
                eventLevel: 'Verbose'
                recordNumber: 100
              }
            ]
          }
        }
        {
          name: 'azsecpack-file-changes'
          extensionName: 'FileChangeDataCollector'
          streams: [
            'Custom-FileChangeEvents'
          ]
          extensionSettings: {
            enableFileContentCollection: true
            monitoredPaths: [
              {
                path: 'C:\\Windows\\System32\\drivers',
                fileIncludePatterns: ['*.sys']
              }
              {
                path: 'C:\\Windows\\System32',
                fileIncludePatterns: ['*.dll', '*.exe']
              }
            ]
            monitorRegistryKeys: [
              {
                path: 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
              }
              {
                path: 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
              }
            ]
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la-destination'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityEvent'
        ]
        destinations: [
          'la-destination'
        ]
      }
      {
        streams: [
          'Microsoft-Perf'
        ]
        destinations: [
          'la-destination'
        ]
      }
      {
        streams: [
          'Microsoft-WindowsEvent'
        ]
        destinations: [
          'la-destination'
        ]
      }
      {
        streams: [
          'Custom-FileChangeEvents'
        ]
        destinations: [
          'la-destination'
        ]
      }
    ]
  }
}

// Create Azure Security Pack Data Collection Rule
resource azsecpackDcr 'Microsoft.Insights/dataCollectionRules@2021-09-01-preview' = {
  name: 'azsecpack-dcr'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    dataCollectionEndpointId: dce.id
    description: 'Azure Security Pack Data Collection Rule'
    dataSources: {
      syslog: []  // Empty for Windows, would be populated for Linux
      extensions: [
        {
          name: 'azsecpack-collection'
          extensionName: 'AzureSecurityPack'
          streams: [
            'Microsoft-SecurityInsights'
          ]
          extensionSettings: {
            securityPackMode: 'Enhanced'
            dataTypes: {
              sysmon: true
              securityEvent: true
              linuxAuditLog: false
              processCreate: true
                             
              fileCreationTime: true
              registryEvent: true
              dnsQuery: true
              networkConnection: true
              imageLoad: true
            }
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la-sentinel'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityInsights'
        ]
        destinations: [
          'la-sentinel'
        ]
      }
    ]
  }
}

// Associate the DCRs with the VM
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = {
  name: 'security-events-dcra'
  scope: existingVm
  properties: {
    dataCollectionRuleId: securityEventsDcr.id
    description: 'Association of data collection rule for security events'
  }
  dependsOn: [
    azureMonitorAgentForWindows
  ]
}

resource azsecpackDcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = {
  name: 'azsecpack-dcra'
  scope: existingVm
  properties: {
    dataCollectionRuleId: azsecpackDcr.id
    description: 'Association of Azure Security Pack data collection rule'
  }
  dependsOn: [
    azureMonitorAgentForWindows
  ]
}

// Grant permissions to the managed identity for Log Analytics
resource logAnalyticsContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: '92aaf0da-9dab-42b6-94a3-d43ce8d16293' // Log Analytics Contributor role
}

// Assign Log Analytics Contributor role to the managed identity
resource laRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: resourceGroup()
  name: guid(resourceGroup().id, managedIdentityId, logAnalyticsContributorRoleDefinition.id)
  properties: {
    roleDefinitionId: logAnalyticsContributorRoleDefinition.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output dataCollectionRuleId string = securityEventsDcr.id
output azsecpackDataCollectionRuleId string = azsecpackDcr.id
output dataCollectionEndpointId string = dce.id
