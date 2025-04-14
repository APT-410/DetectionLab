@description('Name for the Virtual Machine')
param vmName string

@description('Virtual Network name where the VM will be deployed')
param virtualNetworkName string

@description('Subnet ID where the VM will be deployed')
param subnetId string

@description('Virtual machine size')
param vmSize string = 'Standard_D2s_v3'

@description('Admin username')
param adminUsername string

@description('Admin password')
@secure()
param adminPassword string

@description('Log Analytics workspace ID for monitoring')
param workspaceId string

@description('Location for the VM')
param location string = resourceGroup().location

@description('ID of the user-assigned managed identity to assign to the VM')
param managedIdentityId string

@description('Name of the Key Vault, needed for Role Assignment scope')
param keyVaultName string // Parameter to receive KV name from main

// Public IP for VM
resource publicIP 'Microsoft.Network/publicIPAddresses@2022-01-01' = {
  name: '${vmName}-pip'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
    dnsSettings: {
      domainNameLabel: toLower('${vmName}-${uniqueString(resourceGroup().id)}')
    }
  }
}

// Network interface for VM
resource nic 'Microsoft.Network/networkInterfaces@2022-01-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIP.id
          }
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

// Windows VM with user-assigned managed identity
resource vm 'Microsoft.Compute/virtualMachines@2022-03-01' = {
  name: vmName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-Datacenter'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

// Azure Monitor Agent extension
resource azureMonitorAgent 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
  }
}

// Managed Identity extension to make the identity available in the VM
resource managedIdentityExtension 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' = {
  parent: vm
  name: 'ManagedIdentityExtensionForWindows'
  location: location
  properties: {
    publisher: 'Microsoft.ManagedIdentity'
    type: 'ManagedIdentityExtensionForWindows'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    settings: {
      port: 50342
    }
  }
}

// Role assignment for VM to read Key Vault secrets
// Define the built-in role ID
resource keyVaultReaderRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User role ID
}

// Reference the Key Vault resource for the role assignment scope
// We need to get the Key Vault resource based on the name passed in
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
  name: keyVaultName // Use the parameter passed from main
  scope: resourceGroup() // Assuming KV is in the same RG as the VM module deployment
}

// Assign the role to the VM's managed identity
resource vmKeyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  scope: keyVault // Assign role at the Key Vault scope
  name: guid(keyVault.id, managedIdentityId, keyVaultReaderRoleDefinition.id)
  properties: {
    roleDefinitionId: keyVaultReaderRoleDefinition.id
    principalId: reference(managedIdentityId, '2018-11-30').principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output vmName string = vm.name
output vmId string = vm.id
output vmPrivateIp string = nic.properties.ipConfigurations[0].properties.privateIPAddress
output vmFqdn string = publicIP.properties.dnsSettings.fqdn
// Output the client ID of the managed identity assigned to the VM
// This is needed for the manual setup script
output vmManagedIdentityClientId string = reference(managedIdentityId, '2018-11-30').clientId
