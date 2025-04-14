param namePrefix string = 'secLab'
param location string = resourceGroup().location

@description('The object ID of the user or group to grant Key Vault secrets access (e.g., your user ID for initial setup)')
param keyVaultAdminObjectId string

@description('Azure Active Directory tenant ID that should be used for authenticating requests to the key vault')
param tenantId string = subscription().tenantId

@description('Enable RBAC authorization for Key Vault instead of access policies')
param enableRbacAuthorization bool = true

// Variables
var keyVaultName = '${namePrefix}kv${uniqueString(resourceGroup().id)}'

resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard' // Or 'premium' for HSM-backed keys
    }
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableRbacAuthorization: enableRbacAuthorization
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    networkAcls: {
      bypass: 'AzureServices' // Allows trusted services like VM deployment
      defaultAction: 'Deny' // Deny access by default
      ipRules: [] // Add specific IPs if needed
      virtualNetworkRules: [] // Add VNet rules if needed
    }
  }
}

// Role Assignment for the admin user/group (conceptual - requires deploying principal to have Owner role)
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' // Built-in Role ID
resource adminRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableRbacAuthorization) {
  scope: keyVault
  name: guid(keyVault.id, keyVaultAdminObjectId, keyVaultSecretsOfficerRoleId)
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalId: keyVaultAdminObjectId
  }
}

output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
