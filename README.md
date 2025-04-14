# Azure Security Monitoring & Analytics Lab (Event Hubs Architecture)

This project deploys a scalable Azure environment designed for enterprise-grade security log ingestion, real-time processing, SIEM/SOAR capabilities, and large-scale batch analytics/ML.

It utilizes Azure Event Hubs as the central ingestion point for high-volume logs, alongside Azure Monitor Agent providing comprehensive security telemetry directly to Log Analytics from VMs.

**Architecture highlights:**
- Dual ingestion paths: AMA direct to Log Analytics, and high-volume/PaaS via Event Hubs.
- Azure Monitor Agent (AMA) with enhanced Data Collection Rules for VM telemetry.
- Event Hubs for scalable, decoupled high-throughput ingestion.
- Stream Analytics for real-time filtering, enrichment, and detection on the Event Hubs stream.
- Log Analytics and Microsoft Sentinel for core SIEM capabilities and KQL-based analytics.
- Azure Data Lake Storage (ADLS Gen2) for cost-effective long-term archival and batch processing input.
- Synapse Analytics for advanced batch processing, ETL, and ML on data stored in ADLS.

**This revised architecture is suitable for handling high volumes of data (e.g., from ~50k endpoints) cost-effectively.**

## Architecture Overview

(See [architecture_diagram.md](architecture_diagram.md) for the detailed diagram)

This lab demonstrates a flexible architecture handling various log sources:

*   **VMs:** Azure Monitor Agent (AMA) collects standard OS logs, security events, performance data, and Sysmon logs directly into Log Analytics.
*   **Azure PaaS/Other Services:** Diagnostic Settings can route logs either directly to Log Analytics (for immediate SIEM analysis) or to Event Hubs (for high-volume data requiring pre-processing or routing).
*   **High-Volume/Custom Sources (Conceptual):** Other agents or applications *could* be configured to send high-volume data directly to Event Hubs (this path isn't configured by default for the lab VM).

Data ingested into Event Hubs is processed by Azure Stream Analytics for real-time filtering and detection before being routed to Log Analytics (for alerts/SIEM) and/or ADLS (for archival/batch).

## Key Data Flows

1.  **Standard VM Logs:** `VM` -> `AMA` -> `Log Analytics` -> `Sentinel`.
2.  **Azure PaaS Logs (Option 1 - SIEM Focus):** `PaaS Service` -> `Diagnostic Settings` -> `Log Analytics` -> `Sentinel`.
3.  **Azure PaaS/High-Volume Logs (Option 2 - Filtering/Routing Focus):** `PaaS Service/Other Source` -> `Diagnostic Settings/Forwarder` -> `Event Hubs` -> `Stream Analytics` -> (`Log Analytics` and/or `ADLS Gen2`).
4.  **Batch Analytics:** `ADLS Gen2` -> `Synapse Analytics` -> (Results back to `ADLS` or `Log Analytics`).

## Lab Components

*   **Azure Event Hubs:** Central ingestion point for high-volume/routed logs.
*   **Azure Log Analytics Workspace:** Stores curated logs for Sentinel & querying (data from AMA and potentially ASA).
*   **Microsoft Sentinel:** SIEM/SOAR solution.
*   **Azure Stream Analytics:** Real-time filtering, detection, and routing from Event Hubs.
*   **Azure Data Lake Storage (Gen2):** Scalable storage for raw/filtered logs (from ASA) and ML/batch data.
*   **Azure Synapse Analytics:** Platform for big data ETL, joins, and batch ML (primarily reads from ADLS).
*   **Azure Key Vault:** Secure storage for secrets.
*   **Azure Virtual Network / NSG:** Basic networking for test VM and secure access.
*   **Windows Server VM:** Example endpoint generating logs collected by AMA.
*   **Azure Monitor Agent (AMA):** Collects comprehensive Windows logs directly to Log Analytics.
*   **Enhanced Data Collection Rules:** Captures security events, registry changes, file modifications, and performance data via AMA.

## Prerequisites

*   Azure Subscription with sufficient permissions (Owner or Contributor + User Access Administrator for role assignments).
*   Azure CLI installed and configured (`az login`).
*   Git.
*   PowerShell 5.1+ for running deployment scripts.

## Deployment

This lab can be deployed using PowerShell wrapper scripts that utilize Azure Bicep templates.

### Deployment Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/LoggingLab.git
    cd LoggingLab
    ```
2.  **Login to Azure:**
    ```powershell
    # Ensure you are logged into the correct Azure subscription
    az login
    az account list --output table
    # If needed: az account set --subscription "Your Subscription Name or ID"
    ```
3.  **Find your Public IP:** (Required for secure VM access)
    Go to a site like [https://www.whatismyip.com/](https://www.whatismyip.com/) or use:
    ```powershell
    (Invoke-RestMethod -Uri 'https://api.ipify.org').Trim()
    ```
4.  **Run Deployment Script:**
    Open PowerShell **as Administrator** (needed for some setup steps) and run the deployment wrapper script.

    *   **Standard Deployment (Recommended):** Uses the default `MaxLoggingForDetectionDev` profile and auto-generates secure passwords (stored in Key Vault).
        ```powershell
        .\Deploy.ps1 -IpAddress 'YOUR_PUBLIC_IP'
        # Example: .\Deploy.ps1 -IpAddress '203.0.113.5'
        ```

    *   **Specify Resource Group/Location/Prefix:**
        ```powershell
        .\Deploy.ps1 -ResourceGroup 'MySecurityLabRG' -Location 'eastus' -Prefix 'myslab' -IpAddress 'YOUR_PUBLIC_IP'
        ```

    *   **Use Production Tuned Logging:** To deploy with the less verbose logging profile:
        ```powershell
        .\Deploy.ps1 -IpAddress 'YOUR_PUBLIC_IP' -LoggingProfile 'ProductionTuned'
        ```

    *   **(Optional) Manual Password Entry:** If you prefer to set the VM/Synapse admin password manually (less secure, not recommended for production):
        ```powershell
        .\Deploy.ps1 -IpAddress 'YOUR_PUBLIC_IP' -ManualPassword 'YourComplexPasswordHere!'
        # Or combine with other options:
        .\Deploy.ps1 -ResourceGroup 'MySecurityLabRG' -IpAddress 'YOUR_PUBLIC_IP' -ManualPassword 'YourComplexPasswordHere!' -LoggingProfile 'ProductionTuned'
        ```

    The script will:
    *   Prompt for missing mandatory parameters if not provided.
    *   Create a resource group (if it doesn't exist).
    *   Deploy all Azure resources using Bicep (VM, Log Analytics, Sentinel, Key Vault, Storage, Synapse, Network, DCR based on selected profile).
    *   Configure Network Security Groups (NSGs) to allow RDP/Bastion access *only* from the specified IP address.
    *   Generate secure passwords for the VM admin and Synapse SQL admin (unless `-ManualPassword` is used) and store them in Key Vault.
    *   Output necessary information like the VM Public IP, Log Analytics Workspace ID, and Key Vault name.

## Using the Lab

1.  **Generate Test Events:** Log into the test VM (via RDP using its Public IP) and perform actions that generate logs (e.g., failed logins, process creation, run commands). These events should appear in Log Analytics via AMA.
2.  **Verify Data Flow:**
    *   Check Log Analytics for Windows logs collected by AMA (`SecurityEvent`, `Sysmon`, `Perf` tables).
    *   If you configured Diagnostic Settings/ASA: Check Event Hubs metrics, ASA metrics, and the target outputs (Log Analytics custom tables or ADLS).
3.  **Explore Sentinel:** Investigate incidents generated from Log Analytics data, run hunting queries, view workbooks.
4.  **Explore Stream Analytics:** If configured, test its real-time filtering/alerting capabilities.
5.  **Explore Synapse:** Connect to the Synapse workspace, ingest data from ADLS (populated by ASA or LA Export), run example ETL/ML notebooks.

## Cleanup

To avoid ongoing costs, delete the resource group when finished:

```bash
az group delete --name "MalwareLab" --yes --no-wait
```