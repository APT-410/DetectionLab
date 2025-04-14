// dcr-malware-testing.bicep
// DCR configuration optimized for maximum visibility during malware testing.

param location string = resourceGroup().location
param workspaceId string
param vmId string
param managedIdentityId string
param dceId string // Data Collection Endpoint ID passed from main

// Reference to the existing VM
resource existingVm 'Microsoft.Compute/virtualMachines@2022-03-01' existing = {
  name: last(split(vmId, '/'))
}

// Malware Testing DCR: High Verbosity
resource malwareTestingDcr 'Microsoft.Insights/dataCollectionRules@2021-09-01-preview' = {
  name: 'dcr-malware-testing'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    dataCollectionEndpointId: dceId
    description: 'High verbosity data collection for malware testing'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'security-events-verbose'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: [
            // Collect almost all security events
            'Security!*' 
          ]
        }
      ]
      performanceCounters: [
        {
          name: 'system-performance-detailed'
          streams: [
            'Microsoft-Perf'
          ]
          samplingFrequencyInSeconds: 30 // More frequent sampling
          counterSpecifiers: [
            '\\Processor(_Total)\\% Processor Time'
            '\\Memory\\Available Bytes'
            '\\Memory\\% Committed Bytes In Use'
            '\\Memory\\Committed Bytes'
            '\\LogicalDisk(_Total)\\% Free Space'
            '\\LogicalDisk(_Total)\\Free Megabytes'
            '\\PhysicalDisk(_Total)\\% Disk Time'
            '\\PhysicalDisk(_Total)\\Avg. Disk Queue Length'
            '\\Network Interface(*)\\Bytes Received/sec'
            '\\Network Interface(*)\\Bytes Sent/sec'
            '\\Network Interface(*)\\Packets/sec'
            '\\Process(*)\\% Processor Time'
            '\\Process(*)\\Working Set'
            '\\Process(*)\\Private Bytes' // Added
            '\\Process(*)\\Virtual Bytes' // Added
            '\\Process(*)\\Page Faults/sec' // Added
            '\\Process(*)\\Thread Count'
            '\\Process(*)\\Handle Count'
            '\\System\\Processor Queue Length'
            '\\System\\Context Switches/sec'
          ]
        }
      ]
      extensions: [
        {
          name: 'windowsevent-all' // Capture more event logs
          extensionName: 'WindowsEventCollector'
          streams: [
            'Custom-WindowsEventCollector'
          ]
          extensionSettings: {
            events: [
              { name: 'application-events', eventName: 'Application', eventLevel: 'Verbose', recordNumber: 500 }, { name: 'system-events', eventName: 'System', eventLevel: 'Verbose', recordNumber: 500 }, { name: 'security-auditing', eventName: 'Security', eventLevel: 'Verbose', recordNumber: 500 }, { name: 'powershell-operational', eventName: 'Microsoft-Windows-PowerShell/Operational', eventLevel: 'Verbose', recordNumber: 200 }, { name: 'windows-defender', eventName: 'Microsoft-Windows-Windows Defender/Operational', eventLevel: 'Verbose', recordNumber: 200 }, { name: 'smb-client-security', eventName: 'Microsoft-Windows-SmbClient/Security', eventLevel: 'Verbose', recordNumber: 100 }, { name: 'bits-client-operational', eventName: 'Microsoft-Windows-Bits-Client/Operational', eventLevel: 'Verbose', recordNumber: 100 }
            ]
          }
        }, 
        {
          name: 'sysmon-detailed' // Consider using a custom Sysmon config for malware hunting
          extensionName: 'SysmonDataCollector'
          streams: [
            'Custom-SysmonEvents'
          ]
          extensionSettings: {
             // configurationFile: 'path/to/detailed-sysmon-config.xml' // Ideally use a specific config
             defaultConfiguration: true // Fallback to default if no specific config provided
          }
        }, 
        {
          name: 'file-changes-broad' // Monitor broader paths
          extensionName: 'FileChangeDataCollector'
          streams: [
            'Custom-FileChangeEvents'
          ]
          extensionSettings: {
            enableFileContentCollection: true // Consider cost/performance impact
            monitoredPaths: [
              { path: 'C:\\Windows\\System32\\drivers', fileIncludePatterns: ['*.sys'] }, { path: 'C:\\Windows\\System32', fileIncludePatterns: ['*.dll', '*.exe', '*.ps1', '*.bat', '*.vbs'] }, { path: 'C:\\Windows\\SysWOW64', fileIncludePatterns: ['*.dll', '*.exe', '*.ps1', '*.bat', '*.vbs'] }, { path: 'C:\\Program Files', fileIncludePatterns: ['*.exe', '*.dll', '*.ps1', '*.vbs', '*.bat', '*.cmd'] }, { path: 'C:\\Program Files (x86)', fileIncludePatterns: ['*.exe', '*.dll', '*.ps1', '*.vbs', '*.bat', '*.cmd'] }, { path: 'C:\\ProgramData', fileIncludePatterns: ['*.*'] }, { path: 'C:\\Windows\\Temp', fileIncludePatterns: ['*.*'] }, { path: 'C:\\Users\\', fileIncludePatterns: ['*.exe', '*.dll', '*.ps1', '*.vbs', '*.hta', '*.js', '*.lnk'] }
            ]
            monitorRegistryKeys: [
              { path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' }, { path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }, { path: 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run' }, { path: 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }, { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services' }, { path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx' }, { path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' }, { path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }
            ]
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la-destination-malware'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      { streams: [ 'Microsoft-SecurityEvent' ], destinations: [ 'la-destination-malware' ] },
      { streams: [ 'Microsoft-Perf' ], destinations: [ 'la-destination-malware' ] },
      { streams: [ 'Custom-WindowsEventCollector' ], destinations: [ 'la-destination-malware' ] },
      { streams: [ 'Custom-SysmonEvents' ], destinations: [ 'la-destination-malware' ] },
      { streams: [ 'Custom-FileChangeEvents' ], destinations: [ 'la-destination-malware' ] }
    ]
  }
}

// Associate the DCR with the VM
resource malwareDcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = {
  name: 'malware-testing-dcra'
  scope: existingVm
  properties: {
    dataCollectionRuleId: malwareTestingDcr.id
    description: 'Association of malware testing data collection rule'
  }
}

output dataCollectionRuleId string = malwareTestingDcr.id 
