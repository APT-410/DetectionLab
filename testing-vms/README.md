# Testing Virtual Machines

This directory contains the infrastructure templates and deployment scripts for creating test virtual machines that can be used with the Azure Security Monitoring Lab. These testing VMs are separated from the main lab infrastructure to make it easier to create, destroy, and manage test environments.

## Purpose

The testing VMs are designed to:

1. Provide additional endpoints to test security monitoring capabilities
2. Allow for creating malicious or anomalous activities in a controlled environment
3. Test detection rules and alerts without affecting the main lab environment
4. Allow for multiple team members to have their own test environments

## Components

- **Windows Virtual Machine**: For testing Windows-based security events
- **Log Collection**: Collects security logs using Azure Monitor Agent
- **Security Event Collection**: Uses data collection rules to gather security-relevant events

## Deployment Instructions

### Prerequisites

- Completed deployment of the main lab infrastructure (for the Log Analytics workspace)
- Azure CLI installed
- PowerShell

### Deploy a Testing VM

1. From the `testing-vms` directory, run the deployment script:

```powershell
# Using default parameters
.\deploy-test-vm.ps1

# Or specify custom parameters
.\deploy-test-vm.ps1 -ResourceGroup "MyTestVMs" -Location "westus2" -Prefix "mytest" -ManualPassword
```

2. The script will automatically:
   - Find available Log Analytics workspaces to use
   - Create a new resource group for testing VMs
   - Deploy the necessary resources
   - Configure security event collection

### Parameters

- `ResourceGroup`: The resource group to deploy the testing VM to (default: "SecurityTestVMs")
- `Location`: Azure region for deployment (default: "eastus")
- `DeploymentName`: Name for the deployment operation (default: "TestVMDeployment")
- `Prefix`: Prefix for all resource names (default: "testvm")
- `ManualPassword`: Switch to manually specify username and password (default: false)
- `LogAnalyticsWorkspaceId`: Resource ID of an existing Log Analytics workspace. If not specified, the script will try to find one.

## Generating Security Events

After your testing VM is deployed, you can use it to generate security events:

1. Connect to the VM using RDP with the credentials provided by the deployment script
2. Install the Sysmon tool:
   ```powershell
   Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
   Expand-Archive -Path C:\Sysmon.zip -DestinationPath C:\Sysmon -Force
   # Install Sysmon with default config or provide path to your own config file
   # Example using default config:
   C:\Sysmon\Sysmon.exe -i -accepteula 
   # Example using custom config:
   # C:\Sysmon\Sysmon.exe -i C:\path\to\your\sysmon-config.xml
   ```

3. Run test security simulations:
   ```powershell
   # Copy simulation files from the main VM if available, or run your own tests
   # Example of a suspicious command that would generate alerts:
   powershell -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Start-Process calc.exe")))
   ```

## Cleanup

When you're done with the testing VM, you can delete it by removing its resource group:

```powershell
az group delete --name SecurityTestVMs --yes
```

## Architecture Integration

The testing VMs are designed to work with the main Security Lab architecture:

1. They send logs to the same Log Analytics workspace
2. They can be detected by the same alert rules
3. They work with Azure Sentinel dashboards and hunting queries

However, they are deployed in separate resource groups for easier management and cleanup.