param namePrefix string = 'secLab'
param location string = resourceGroup().location

@description('Address space for the Virtual Network')
param vnetAddressPrefix string = '10.10.0.0/16'

@description('Address space for the default subnet')
param defaultSubnetAddressPrefix string = '10.10.1.0/24'

@description('Your public IP address or CIDR range to allow RDP/SSH access via NSG. Use * for testing only.')
param allowedSourceIpAddress string = '*'

// Variables
var virtualNetworkName = '${namePrefix}-vnet'
var defaultSubnetName = 'default'
var networkSecurityGroupName = '${namePrefix}-nsg'

// Network Security Group
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: networkSecurityGroupName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowRDPFromMyIP' // Allow RDP for VM config (restrict source IP)
        properties: {
          description: 'Allow RDP from specified source IP'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389' // Standard RDP port
          sourceAddressPrefix: allowedSourceIpAddress
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100 // High priority to allow RDP
          direction: 'Inbound'
        }
      }
      // Add other rules if needed, e.g., deny all other inbound by default
    ]
  }
}

// Virtual Network
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: virtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: defaultSubnetName
        properties: {
          addressPrefix: defaultSubnetAddressPrefix
          networkSecurityGroup: {
            id: nsg.id // Apply NSG to the default subnet
          }
          // serviceEndpoints: [ ... ] // Add if needed
          // privateEndpointNetworkPolicies: 'Enabled' // Consider disabling for Private Endpoints
        }
      }
      // Add subnets for Private Endpoints if needed
    ]
  }
}

output virtualNetworkName string = virtualNetwork.name
output virtualNetworkId string = virtualNetwork.id
output defaultSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetwork.name, defaultSubnetName)
