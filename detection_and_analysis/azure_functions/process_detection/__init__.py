import json
import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.monitor.query import LogsQueryClient
from datetime import datetime, timedelta
import os
import re

# MITRE ATT&CK techniques covered:
# T1059 - Command and Scripting Interpreter
# T1105 - Ingress Tool Transfer
# T1218 - System Binary Proxy Execution

def main(event: func.EventHubEvent):
    """
    Process security detection for malicious command patterns
    This function analyzes process execution events to detect
    suspicious command-line patterns based on MITRE ATT&CK techniques.
    
    Args:
        event: Event Hub event containing process execution data
    """
    try:
        # Initialize logging
        logging.info('Python process detection function triggered')
        
        # Parse the event body
        event_body = event.get_body().decode('utf-8')
        event_data = json.loads(event_body)
        
        # Process metadata
        hostname = event_data.get('metadata', {}).get('hostname', 'unknown')
        timestamp = event_data.get('metadata', {}).get('timestamp', datetime.utcnow().isoformat())
        
        # Extract process info for analysis
        process_name = event_data.get('process_name', '')
        command_line = event_data.get('command_line', '')
        user_name = event_data.get('user_name', '')
        process_id = event_data.get('process_id', 0)
        parent_process_name = event_data.get('parent_process_name', '')
        parent_process_id = event_data.get('parent_process_id', 0)
        
        logging.info(f"Analyzing process: {process_name} with command: {command_line}")
        
        # Analyze for suspicious patterns
        # 1. PowerShell with encoded commands (potential obfuscation)
        encoded_cmd_pattern = re.compile(r'-e\s*[a-zA-Z0-9+/=]{20,}|-enc\s*[a-zA-Z0-9+/=]{20,}|-encodedcommand\s*[a-zA-Z0-9+/=]{20,}', re.IGNORECASE)
        
        # 2. Common download commands (potential malware delivery)
        download_pattern = re.compile(r'(wget|curl|invoke-webrequest|downloadfile|downloadstring|start-bitstransfer|certutil -urlcache)', re.IGNORECASE)
        
        # 3. Suspicious command execution patterns (potential lateral movement or privilege escalation)
        suspicious_exec = re.compile(r'(iex\s*\(|invoke-expression|rundll32|regsvr32 /s|mshta|wmic\s+.*\s+call|wmic\s+.*\s+exec)', re.IGNORECASE)
        
        # Evaluate detection logic and set alert severity
        severity = 'Informational'
        alert_title = None
        mitre_technique = None
        detection_details = []
        
        # Check for encoded PowerShell commands
        if encoded_cmd_pattern.search(command_line):
            severity = 'High'
            alert_title = 'Suspicious PowerShell Encoded Command'
            mitre_technique = 'T1059.001'
            detection_details.append(f"PowerShell encoded command detected: {command_line[:100]}...")
        
        # Check for download operations
        elif download_pattern.search(command_line):
            severity = 'Medium'
            alert_title = 'Potentially Malicious File Download'
            mitre_technique = 'T1105'
            detection_details.append(f"File download operation detected: {command_line[:100]}...")
        
        # Check for suspicious command execution
        elif suspicious_exec.search(command_line):
            severity = 'High'
            alert_title = 'Suspicious Command Execution Pattern'
            mitre_technique = 'T1218'
            detection_details.append(f"Malicious command execution pattern detected: {command_line[:100]}...")
        
        # Check for malicious process chains (common malware behavior)
        elif parent_process_name in ('explorer.exe', 'services.exe') and process_name.lower() in ('powershell.exe', 'cmd.exe') and len(command_line) > 100:
            severity = 'Medium'
            alert_title = 'Suspicious Process Chain'
            mitre_technique = 'T1059'
            detection_details.append(f"Unusual process chain: {parent_process_name} -> {process_name}")
        
        # Generate alert if needed
        if alert_title:
            # Create alert body
            alert = {
                'timestamp': timestamp,
                'hostname': hostname,
                'alert_title': alert_title,
                'alert_severity': severity,
                'mitre_technique': mitre_technique,
                'detection_details': detection_details,
                'process_info': {
                    'process_name': process_name,
                    'process_id': process_id,
                    'command_line': command_line,
                    'user_name': user_name,
                    'parent_process': parent_process_name,
                    'parent_process_id': parent_process_id
                },
                'event_time': datetime.utcnow().isoformat()
            }
            
            # Log the alert
            logging.info(f"Security alert generated: {alert_title} - {severity}")
            logging.info(json.dumps(alert))
            
            # Send alert to Log Analytics
            if send_alert_to_log_analytics(alert):
                logging.info("Alert sent to Log Analytics successfully")
            else:
                logging.error("Failed to send alert to Log Analytics")
            
            # For high severity alerts, perform context enrichment
            if severity == 'High':
                enrich_alert_with_context(alert)
        else:
            logging.info("No suspicious activity detected")
    
    except Exception as e:
        logging.error(f"Error processing event: {str(e)}")

def send_alert_to_log_analytics(alert):
    """
    Send security alert to Log Analytics workspace
    
    Args:
        alert: Dictionary containing alert details
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Use the Log Analytics API with managed identity
        # This is a simplified example - in production you would use the Log Analytics Data Collector API
        # or an Azure Function output binding
        logging.info("Sending alert to Log Analytics...")
        
        # In production code, implement the actual API call
        # For this example, we'll just return success
        return True
    except Exception as e:
        logging.error(f"Error sending alert to Log Analytics: {str(e)}")
        return False

def enrich_alert_with_context(alert):
    """
    Enrich high-severity alerts with additional context from Log Analytics
    
    Args:
        alert: Dictionary containing alert details
    """
    try:
        # Use managed identity for authentication
        credential = ManagedIdentityCredential()
        
        # Initialize Log Analytics client
        logs_client = LogsQueryClient(credential)
        
        # Query for related events within a time window
        workspace_id = os.environ.get("WORKSPACE_ID")
        hostname = alert.get('hostname')
        process_name = alert.get('process_info', {}).get('process_name')
        
        # Set time range for contextual query (15 minutes before alert)
        timestamp = datetime.fromisoformat(alert.get('timestamp').replace('Z', '+00:00'))
        start_time = timestamp - timedelta(minutes=15)
        end_time = timestamp + timedelta(minutes=5)
        
        # Construct KQL query for network connections from process
        query = f"""
        NetworkEvents_CL
        | where TimeGenerated between(datetime({start_time.isoformat()}) .. datetime({end_time.isoformat()}))
        | where HostName_s == "{hostname}" and ProcessName_s == "{process_name}"
        | project TimeGenerated, HostName_s, ProcessName_s, LocalIP_s, RemoteIP_s, RemotePort_d
        | take 10
        """
        
        logging.info(f"Querying for contextual data: {query}")
        
        # Execute query (commented out as this is a simplified example)
        # response = logs_client.query_workspace(workspace_id, query, timespan=(start_time, end_time))
        # logging.info(f"Found {len(response.tables[0].rows)} related network events")
        
        # In a real implementation, you would:
        # 1. Query for related events (network, file, registry)
        # 2. Add the context to the alert
        # 3. Update the alert in Log Analytics
        
        logging.info("Alert enrichment complete")
    except Exception as e:
        logging.error(f"Error enriching alert with context: {str(e)}")