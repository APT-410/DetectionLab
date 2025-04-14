// dcr-production-tuned.bicep
// DCR configuration tuned for production monitoring (balances visibility and cost).

param location string = resourceGroup().location
param workspaceId string
param vmId string
param managedIdentityId string
param dceId string // Data Collection Endpoint ID passed from main

// Reference to the existing VM
resource existingVm 'Microsoft.Compute/virtualMachines@2022-03-01' existing = {
  name: last(split(vmId, '/'))
}

// Production Tuned DCR: Balanced Verbosity
resource productionDcr 'Microsoft.Insights/dataCollectionRules@2021-09-01-preview' = {
  name: 'dcr-production-tuned'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    dataCollectionEndpointId: dceId
    description: 'Tuned data collection rule for production monitoring'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'security-events-tuned'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: [
            // Focus on high-value security events
            'Security!*[System[(EventID=4624 or EventID=4625)]]', // Logon/logoff events
            'Security!*[System[(EventID=4648)]]', // Explicit credential logons
            'Security!*[System[(EventID=4672 or EventID=4673)]]', // Special privileges assigned
            'Security!*[System[(EventID=4688)]]', // Process creation
            'Security!*[System[(EventID=4663)]]', // Attempt to access object (can be noisy)
            'Security!*[System[(EventID=5156)]]', // Filtering Platform Connection Allowed (can be noisy)
            'Security!*[System[(EventID=4697)]]', // Service installation
            'Security!*[System[(EventID=4698)]]', // Scheduled task created
            'Security!*[System[(EventID=4719)]]', // System audit policy changes
            'Security!*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4738)]]', // User account changes
            'Security!*[System[(EventID=4732 or EventID=4733 or EventID=4756)]]', // Group membership changes
            'Security!*[System[(EventID=4103 or EventID=4104)]]', // PowerShell execution
            'Security!*[System[(EventID=1102)]]' // Audit log cleared
          ]
        }
      ]
      performanceCounters: [
        {
          name: 'system-performance-standard'
          streams: [
            'Microsoft-Perf'
          ]
          samplingFrequencyInSeconds: 60 // Standard sampling
          counterSpecifiers: [
            '\\Processor(_Total)\\% Processor Time'
            '\\Memory\\Available Bytes'
            '\\Memory\\% Committed Bytes In Use'
            '\\LogicalDisk(_Total)\\% Free Space'
            '\\PhysicalDisk(_Total)\\% Disk Time'
            '\\Network Interface(*)\\Bytes Total/sec'
            '\\System\\Processor Queue Length'
          ]
        }
      ]
      extensions: [
        {
          name: 'windowsevent-critical' // Collect critical/warning Application/System logs
          extensionName: 'WindowsEventCollector'
          streams: [
            'Custom-WindowsEventCollector'
          ]
          extensionSettings: {
            events: [
              { name: 'application-events', eventName: 'Application', eventLevel: 'Warning', recordNumber: 100 }, { name: 'system-events', eventName: 'System', eventLevel: 'Warning', recordNumber: 100 }, { name: 'security-auditing', eventName: 'Security', eventLevel: 'Informational', recordNumber: 100, filter: '*[System/EventID=4688]' }
            ]
          }
        }, 
        {
          name: 'sysmon-standard' // Use default Sysmon config
          extensionName: 'SysmonDataCollector'
          streams: [
            'Custom-SysmonEvents'
          ]
          extensionSettings: {
             defaultConfiguration: true 
          }
        }, 
        {
          name: 'file-changes-targeted' // Monitor only essential paths
          extensionName: 'FileChangeDataCollector'
          streams: [
            'Custom-FileChangeEvents'
          ]
          extensionSettings: {
            enableFileContentCollection: false // Disable content collection for performance
            monitoredPaths: [
              { path: 'C:\\Windows\\System32\\drivers', fileIncludePatterns: ['*.sys'] }, { path: 'C:\\Windows\\System32', fileIncludePatterns: ['*.dll', '*.exe'] }, { path: 'C:\\Windows\\SysWOW64', fileIncludePatterns: ['*.dll', '*.exe'] }
            ]
            monitorRegistryKeys: [
              { path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' }, { path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }, { path: 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run' }, { path: 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }
            ]
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la-destination-prod'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      { streams: [ 'Microsoft-SecurityEvent' ], destinations: [ 'la-destination-prod' ] },
      { streams: [ 'Microsoft-Perf' ], destinations: [ 'la-destination-prod' ] },
      { streams: [ 'Custom-WindowsEventCollector' ], destinations: [ 'la-destination-prod' ] },
      { streams: [ 'Custom-SysmonEvents' ], destinations: [ 'la-destination-prod' ] },
      { streams: [ 'Custom-FileChangeEvents' ], destinations: [ 'la-destination-prod' ] }
    ]
  }
}

// Associate the DCR with the VM
resource productionDcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = {
  name: 'production-tuned-dcra'
  scope: existingVm
  properties: {
    dataCollectionRuleId: productionDcr.id
    description: 'Association of production tuned data collection rule'
  }
}

output dataCollectionRuleId string = productionDcr.id 
