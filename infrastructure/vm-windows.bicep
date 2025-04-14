param namePrefix string = 'secLab'
param location string = resourceGroup().location

@description('Admin username for the VM')
param adminUsername string

@description('Admin password for the VM. Use Key Vault integration for production.')
@secure()
param adminPassword string

@description('Size of the VM')
param vmSize string = 'Standard_D2s_v3'

@description('ID of the default subnet to deploy the VM into')
param subnetId string

@description('Name of the Key Vault for role assignment scope')
param keyVaultName string // Required for role assignment

// Variables
var vmName = '${namePrefix}vm${uniqueString(resourceGroup().id)}'
var nicName = '${vmName}-nic'
var publicIpName = '${vmName}-pip' // Added variable for Public IP Name
var osDiskName = '${vmName}-osdisk'
var vmImagePublisher = 'MicrosoftWindowsServer'
var vmImageOffer = 'WindowsServer'
var vmImageSku = '2022-datacenter-azure-edition'
var vmImageVersion = 'latest'

// Public IP for the VM
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: publicIpName
  location: location
  sku: {
    name: 'Standard' // Use Standard SKU for better availability options
  }
  properties: {
    publicIPAllocationMethod: 'Static' // Static is recommended for VMs
    dnsSettings: {
      domainNameLabel: toLower('${vmName}-${uniqueString(resourceGroup().id)}')
    }
  }
}

// Network Interface (Attach Public IP)
resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
          publicIPAddress: { 
            id: publicIp.id // Associate the Public IP with the NIC
          }
        }
      }
    ]
  }
}

// Virtual Machine
resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  identity: {
    // Defaulting to System Assigned Managed Identity
    type: 'SystemAssigned'
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
        provisionVMAgent: true
        enableAutomaticUpdates: true
        patchSettings: {
          patchMode: 'AutomaticByOS'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: vmImagePublisher
        offer: vmImageOffer
        sku: vmImageSku
        version: vmImageVersion
      }
      osDisk: {
        name: osDiskName
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
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

// Role assignment for VM System-Assigned Identity to read Key Vault secrets
// Define the built-in role ID
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User role ID

// Reference the Key Vault resource
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  name: keyVaultName
  // scope: resourceGroup() // Scope to RG if KV is in the same RG
}

// Assign the role to the VM's system-assigned managed identity
// Note: Requires deploying principal to have Owner rights or equivalent.
resource vmKeyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault // Assign role at the Key Vault scope
  name: guid(vm.id, keyVault.id, keyVaultSecretsUserRoleId) // Use VM resource ID for guid uniqueness
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: vm.identity.principalId // Use the system-assigned principal ID
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output vmName string = vm.name
output vmId string = vm.id
output vmSystemAssignedPrincipalId string = vm.identity.principalId
output publicIpAddress string = publicIp.properties.ipAddress // Output the actual IP address
output publicIpFqdn string = publicIp.properties.dnsSettings.fqdn // Output the FQDN
