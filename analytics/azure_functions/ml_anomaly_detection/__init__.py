import logging
import json
import azure.functions as func
from datetime import datetime, timedelta
import os
import uuid
import numpy as np
import joblib
import tempfile
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient, PartitionKey, exceptions

# Constants from environment variables or defaults
MANAGED_IDENTITY_CLIENT_ID = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
COSMOS_DB_ENDPOINT = os.environ.get("COSMOS_DB_ENDPOINT")
COSMOS_DB_NAME = os.environ.get("COSMOS_DB_NAME", "security-db")
COSMOS_EVENTS_CONTAINER_NAME = os.environ.get("COSMOS_EVENTS_CONTAINER", "security-events")
COSMOS_BEHAVIOR_CONTAINER_NAME = os.environ.get("COSMOS_BEHAVIOR_CONTAINER", "behavior-analytics")
STORAGE_ACCOUNT_NAME = os.environ.get("STORAGE_ACCOUNT_NAME")
MODELS_CONTAINER_NAME = os.environ.get("MODELS_CONTAINER", "ml-models") # Renamed for clarity
TIME_WINDOW_HOURS = int(os.environ.get("TIME_WINDOW_HOURS", "48"))
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "-0.1")) # IF score threshold
MIN_EVENTS_FOR_ANALYSIS = int(os.environ.get("MIN_EVENTS_FOR_ANALYSIS", "50"))

def main(timer: func.TimerRequest, context: func.Context) -> None:
    """
    ML-based anomaly detection function that runs on a schedule.
    This function:
    1. Retrieves security events from Cosmos DB for active hosts.
    2. Applies ML techniques (Isolation Forest) to identify anomalous process behavior.
    3. Stores detection results back to Cosmos DB.

    Timer trigger: runs on schedule defined in function.json
    """
    utc_timestamp = datetime.utcnow().replace(tzinfo=None).isoformat()
    logging.info(f'ML Anomaly Detection function triggered at: {utc_timestamp}')

    if not all([COSMOS_DB_ENDPOINT, STORAGE_ACCOUNT_NAME]):
        logging.error("Missing required environment variables: COSMOS_DB_ENDPOINT, STORAGE_ACCOUNT_NAME")
        return # Exit if essential config is missing

    try:
        # Initialize credentials and clients
        credential = get_credential(MANAGED_IDENTITY_CLIENT_ID)

        # Get Cosmos DB connection
        cosmos_client = CosmosClient(COSMOS_DB_ENDPOINT, credential=credential)

        # Get database and container references
        database = cosmos_client.get_database_client(COSMOS_DB_NAME)
        events_container = database.get_container_client(COSMOS_EVENTS_CONTAINER_NAME)
        behavior_container = database.get_container_client(COSMOS_BEHAVIOR_CONTAINER_NAME)

        # Get storage account for model persistence
        blob_service_client = BlobServiceClient(
            account_url=f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net",
            credential=credential
        )

        # Process recent events by host
        process_hosts(events_container, behavior_container, blob_service_client, MODELS_CONTAINER_NAME, TIME_WINDOW_HOURS)

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Cosmos DB error: {e.status_code} - {e.message}")
    except Exception as e:
        logging.error(f"Error in ML anomaly detection function: {str(e)}", exc_info=True)
        # Depending on requirements, might want to raise to indicate failure to the Functions runtime


def get_credential(client_id=None):
    """Get the appropriate Azure credential based on environment"""
    try:
        if client_id:
            # Use the provided managed identity client ID
            credential = ManagedIdentityCredential(client_id=client_id)
            logging.info(f"Using specified managed identity with client ID: {client_id}")
        else:
            # Try with system-assigned or default user-assigned managed identity
            credential = ManagedIdentityCredential()
            logging.info("Using default managed identity (system or user-assigned)")

        # Test credential - optional, but helps diagnose issues early
        # credential.get_token("https://management.azure.com/.default")

        return credential
    except Exception as e:
        logging.warning(f"Managed identity credential failed: {str(e)}. Falling back to DefaultAzureCredential (check environment/local setup).")
        # DefaultAzureCredential will try environment variables, VS Code, Azure CLI etc.
        return DefaultAzureCredential()


def process_hosts(events_container, behavior_container, blob_service_client, storage_container_name, time_window_hours):
    """Process events by host to detect anomalies"""
    current_time_utc = datetime.utcnow()
    start_time_iso = (current_time_utc - timedelta(hours=time_window_hours)).isoformat() + "Z" # ISO 8601 format with Z for UTC

    # Query for unique hosts that have had events in the specified time window
    hosts = get_active_hosts(events_container, start_time_iso)
    logging.info(f"Found {len(hosts)} active hosts in the last {time_window_hours} hours.")

    for host in hosts:
        logging.info(f"Processing host: {host}")

        try:
            # Get process events for this host in the time window
            process_events = get_process_events(events_container, host, start_time_iso)

            if len(process_events) < MIN_EVENTS_FOR_ANALYSIS:
                logging.warning(f"Insufficient events for ML analysis for host {host}. Need at least {MIN_EVENTS_FOR_ANALYSIS}, got {len(process_events)}")
                continue

            # Apply ML to detect anomalies - both point anomalies and behavioral shifts
            behavioral_anomalies = detect_behavioral_anomalies(process_events, host, blob_service_client, storage_container_name)

            # Store the results in the behavior analytics container
            if behavioral_anomalies:
                store_behavioral_anomalies(behavior_container, behavioral_anomalies)
                logging.info(f"Stored {len(behavioral_anomalies)} behavioral anomalies for host {host}")

        except exceptions.CosmosHttpResponseError as e:
            logging.error(f"Cosmos DB error processing host {host}: {e.status_code} - {e.message}")
        except Exception as e:
            logging.error(f"Error processing host {host}: {str(e)}", exc_info=True)


def get_active_hosts(events_container, start_time_iso):
    """Get the list of distinct hostnames that have had events in the time window"""
    logging.info(f"Querying distinct hosts since {start_time_iso}")
    query = f"""
    SELECT DISTINCT VALUE c.hostname
    FROM c
    WHERE c.timestamp >= @start_time
    AND IS_DEFINED(c.hostname)
    """
    parameters = [{"name": "@start_time", "value": start_time_iso}]

    try:
        # Enable cross-partition query as hostname might not be partition key
        results = list(events_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        hosts = [item for item in results if item] # Filter out potential null/empty hostnames
        logging.info(f"Found hosts: {hosts}")
        return hosts
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to query active hosts: {e.message}")
        return []


def get_process_events(events_container, hostname, start_time_iso):
    """Get process events for the specified host in the given time window"""
    logging.info(f"Querying process events for host '{hostname}' since {start_time_iso}")
    # Assuming 'eventType' field exists to filter process events, adjust if needed
    # Assuming 'hostname' is the partition key for efficiency, adjust query/options if not
    query = f"""
    SELECT *
    FROM c
    WHERE c.hostname = @hostname
    AND c.timestamp >= @start_time
    AND c.eventType = 'ProcessEvent'
    """ # Add AND c.eventType = 'ProcessEvent' or similar filter if needed
    parameters = [
        {"name": "@hostname", "value": hostname},
        {"name": "@start_time", "value": start_time_iso}
    ]

    try:
        # If hostname is the partition key, this query is efficient.
        # If not, set enable_cross_partition_query=True (less efficient).
        # Check your Cosmos DB container's partition key strategy.
        results = list(events_container.query_items(
            query=query,
            parameters=parameters,
            partition_key=hostname # Specify partition key if it's hostname
            # enable_cross_partition_query=True # Use if hostname is NOT the partition key
        ))
        logging.info(f"Retrieved {len(results)} process events for host {hostname}.")
        return results
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to query process events for host {hostname}: {e.message}")
        return []


def detect_behavioral_anomalies(process_events, hostname, blob_service_client, storage_container_name):
    """Apply ML techniques to identify behavioral anomalies in process execution"""
    try:
        # Convert to pandas DataFrame
        df = pd.DataFrame(process_events)

        # Convert timestamp to datetime objects if they are strings
        if 'timestamp' in df.columns and isinstance(df['timestamp'].iloc[0], str):
            df['timestamp_dt'] = pd.to_datetime(df['timestamp'])
        else:
            df['timestamp_dt'] = df['timestamp'] # Assume already datetime if not string

        # Feature extraction and engineering
        features_df = extract_features(df)

        # Check if feature extraction was successful
        if features_df.empty or features_df.isnull().values.any():
             logging.error(f"Feature extraction resulted in empty or NaN data for host {hostname}. Skipping analysis.")
             return []

        # Load or create host-specific model
        model = load_or_create_model(hostname, blob_service_client, storage_container_name)

        # Update model with recent data (online learning simulation)
        # NOTE: Retraining Isolation Forest on each run is computationally expensive
        # and not true online learning. Consider periodic retraining on a larger baseline
        # or using models supporting incremental updates in production.
        model = update_model(model, features_df)

        # Save updated model
        save_model(model, hostname, blob_service_client, storage_container_name)

        # Score the data for anomalies
        # Ensure features used for scoring match those used for training
        scores = score_anomalies(model, features_df)

        # Generate results for all anomalies (scores below threshold)
        anomaly_results = []
        # Use the constant ANOMALY_THRESHOLD
        # threshold = float(os.environ.get("ANOMALY_THRESHOLD", "-0.1"))

        # Get original event data corresponding to the features
        # Ensure index alignment if any rows were dropped during feature extraction
        aligned_events = df.loc[features_df.index]

        for i, score in enumerate(scores):
            if score <= ANOMALY_THRESHOLD:
                # Get the original event using the index from features_df
                original_event_index = features_df.index[i]
                event = aligned_events.loc[original_event_index].to_dict()

                # Prepare features dictionary from the original event for the record
                event_features = {
                    'cmdLength': event.get('cmd_length'),
                    'specialChars': event.get('special_chars'),
                    'hasNetwork': event.get('has_network'),
                    'hasEncoded': event.get('has_encoded'),
                    'isAdmin': event.get('is_admin'),
                    'processFreq': features_df.loc[original_event_index, 'process_frequency'],
                    'parentFreq': features_df.loc[original_event_index, 'parent_frequency'],
                    'processParentFreq': features_df.loc[original_event_index, 'process_parent_frequency']
                }

                anomaly_record = {
                    # Use a consistent ID structure, ensure 'id' is unique for upsert
                    'id': f"behavior-{hostname}-{event.get('id', uuid.uuid4())}",
                    'entityId': f"{hostname}-{event.get('process_name', 'unknown')}-{str(uuid.uuid4())[:8]}", # Example entity ID
                    'entityType': 'process',
                    'hostname': hostname, # Add partition key field if different from hostname
                    'processName': event.get('process_name'),
                    'parentProcessName': event.get('parent_process_name'),
                    'anomalyScore': float(score), # Keep original score (negative is anomalous)
                    'anomalyThreshold': ANOMALY_THRESHOLD,
                    'timestamp': event.get('timestamp'), # Original event timestamp
                    'eventId': event.get('id'), # Link back to original event
                    'detectionTime': datetime.utcnow().isoformat() + "Z",
                    'anomalyType': 'behavioral',
                    'features': event_features,
                    'severity': calculate_severity(score, event),
                    'mitreTactic': estimate_mitre_tactic(event)
                    # Add TTL field if desired for automatic cleanup in Cosmos DB
                    # 'ttl': 86400 * 30 # 30 days
                }
                anomaly_results.append(anomaly_record)

        return anomaly_results

    except Exception as e:
        logging.error(f"Error in anomaly detection for host {hostname}: {str(e)}", exc_info=True)
        return []


def extract_features(df):
    """Extract and normalize features for ML analysis"""
    # Define feature columns expected from the input data (adjust based on actual event schema)
    # Ensure these fields exist in the Cosmos DB documents
    required_cols = ['process_name', 'parent_process_name', 'cmd_length',
                     'special_chars', 'has_network', 'has_encoded', 'is_admin', 'timestamp_dt']

    # Check if required columns exist
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        logging.error(f"Missing required columns for feature extraction: {missing_cols}")
        return pd.DataFrame() # Return empty DataFrame

    # Select relevant features for anomaly detection
    # Use timestamp_dt for time features
    df['day_of_week'] = df['timestamp_dt'].dt.weekday
    df['hour_of_day'] = df['timestamp_dt'].dt.hour

    feature_cols = ['cmd_length', 'special_chars', 'has_network', 'has_encoded',
                    'is_admin', 'day_of_week', 'hour_of_day']

    # Basic feature set - handle potential non-numeric types gracefully
    features = df[feature_cols].copy()
    for col in features.columns:
        features[col] = pd.to_numeric(features[col], errors='coerce') # Coerce errors to NaN

    # Drop rows with NaN values resulting from coercion or missing data
    features.dropna(axis=0, how='any', inplace=True)
    if features.empty:
        logging.warning("DataFrame became empty after handling non-numeric data or NaNs.")
        return pd.DataFrame()

    # --- Frequency Features ---
    # Calculate frequencies based on the original DataFrame before dropping NaNs
    process_counts = df['process_name'].value_counts(normalize=True)
    parent_counts = df['parent_process_name'].value_counts(normalize=True)
    process_parent_pairs = df['process_name'].astype(str) + '|' + df['parent_process_name'].astype(str)
    pair_counts = process_parent_pairs.value_counts(normalize=True)

    # Map frequencies to the features DataFrame, using its index
    features['process_frequency'] = df.loc[features.index, 'process_name'].map(process_counts).fillna(0)
    features['parent_frequency'] = df.loc[features.index, 'parent_process_name'].map(parent_counts).fillna(0)
    features['process_parent_frequency'] = (df.loc[features.index, 'process_name'].astype(str) + '|' + df.loc[features.index, 'parent_process_name'].astype(str)).map(pair_counts).fillna(0)

    # --- Normalization ---
    # Normalize only numeric features that require scaling
    scaler = StandardScaler()
    numeric_features_to_scale = ['cmd_length', 'special_chars', 'process_frequency',
                                 'parent_frequency', 'process_parent_frequency',
                                 'day_of_week', 'hour_of_day'] # Scale time features too

    # Ensure columns exist before scaling
    valid_numeric_features = [col for col in numeric_features_to_scale if col in features.columns]

    if valid_numeric_features:
        features[valid_numeric_features] = scaler.fit_transform(features[valid_numeric_features])
    else:
        logging.warning("No valid numeric features found to scale.")
        return pd.DataFrame() # Return empty if no features to scale

    return features


def load_or_create_model(hostname, blob_service_client, storage_container_name):
    """Load existing model from blob storage or create a new one"""
    model_filename = f"{hostname}_isolation_forest.pkl"
    container_client = blob_service_client.get_container_client(storage_container_name)
    blob_client = container_client.get_blob_client(model_filename)

    try:
        # Check if blob exists before attempting download
        if blob_client.exists():
            logging.info(f"Loading existing model for host {hostname} from {storage_container_name}/{model_filename}")

            # Download to a temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                download_stream = blob_client.download_blob()
                temp_file.write(download_stream.readall())
                temp_file_path = temp_file.name

            # Load the model from the temporary file
            model = joblib.load(temp_file_path)

            # Clean up
            os.remove(temp_file_path)
            logging.info(f"Model loaded successfully for host {hostname}")
            return model
        else:
             logging.info(f"No existing model found for host {hostname}. Creating a new one.")

    except Exception as e:
        # Log error but proceed to create a new model
        logging.warning(f"Could not load model for {hostname} from blob storage: {str(e)}. Creating a new one.")

    # If no model exists or there was an error loading, create a new one
    # Consider adjusting parameters based on expected data characteristics
    model = IsolationForest(
        n_estimators=100,       # Number of trees
        max_samples='auto',     # Number of samples per tree
        contamination='auto',   # Let the model estimate contamination, or set explicitly e.g., 0.01 for 1%
        max_features=1.0,       # Use all features
        bootstrap=False,        # Don't use bootstrap sampling
        n_jobs=-1,              # Use all available CPU cores
        random_state=42         # For reproducibility
    )
    # Note: The model is not fitted here; it will be fitted in update_model

    return model


def update_model(model, features):
    """Update the model with new data"""
    # For Isolation Forest, fit() replaces any previous training.
    # This simulates retraining on the current window's data.
    logging.info(f"Fitting/Retraining Isolation Forest model with {len(features)} samples...")
    try:
        # Ensure features DataFrame is not empty and contains valid data
        if features.empty:
            logging.error("Cannot update model with empty features DataFrame.")
            return model # Return the existing model without fitting

        # Check for NaNs/Infs again before fitting
        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
             logging.error("Features contain NaN or Inf values before fitting. Check feature extraction.")
             # Optionally, handle NaNs e.g., features.fillna(0, inplace=True) or drop rows
             return model # Return existing model

        model.fit(features)
        logging.info("Model fitting complete.")
    except Exception as e:
        logging.error(f"Error during model fitting: {str(e)}", exc_info=True)
        # Return the unfitted or previously fitted model in case of error
    return model


def save_model(model, hostname, blob_service_client, storage_container_name):
    """Save the updated model to blob storage"""
    model_filename = f"{hostname}_isolation_forest.pkl"
    container_client = blob_service_client.get_container_client(storage_container_name)
    blob_client = container_client.get_blob_client(model_filename)

    try:
        # Create a temporary file and save the model
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            joblib.dump(model, temp_file.name)
            temp_file_path = temp_file.name

        # Upload to blob storage, overwriting if exists
        with open(temp_file_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)

        # Clean up
        os.remove(temp_file_path)
        logging.info(f"Model saved for host {hostname} to {storage_container_name}/{model_filename}")

    except Exception as e:
        logging.error(f"Error saving model for host {hostname}: {str(e)}", exc_info=True)
        # Clean up temp file even if upload fails
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def score_anomalies(model, features):
    """Score data points using the model and return anomaly scores"""
    logging.info(f"Scoring {len(features)} samples for anomalies...")
    try:
        # Ensure features are in the correct format (e.g., numpy array or DataFrame)
        # Check for NaNs/Infs before scoring
        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
             logging.error("Features contain NaN or Inf values before scoring. Check feature extraction.")
             # Handle NaNs/Infs or return default scores
             return np.zeros(len(features)) # Return neutral scores (0)

        # decision_function returns scores where lower values are more anomalous
        scores = model.decision_function(features)
        logging.info("Scoring complete.")
        return scores
    except Exception as e:
        logging.error(f"Error during anomaly scoring: {str(e)}", exc_info=True)
        # Return neutral scores in case of error
        return np.zeros(len(features))


def calculate_severity(score, event):
    """Calculate severity based on anomaly score and event characteristics"""
    # Isolation Forest score: lower is more anomalous. Threshold is negative.
    # Map score relative to threshold onto a 0-1 scale.
    # Score at threshold = 0.5 severity. More negative = higher severity.
    try:
        # Normalize score relative to threshold (assuming threshold is negative)
        # A score far below threshold should approach 1.0
        normalized_score = (ANOMALY_THRESHOLD - score) / abs(ANOMALY_THRESHOLD) if ANOMALY_THRESHOLD != 0 else abs(score)
        base_severity = np.clip(normalized_score * 0.5 + 0.5, 0, 1) # Scale to 0.5-1.0 range based on score

        # Adjust based on risk factors (ensure fields exist)
        if event.get('is_admin') == 1:
            base_severity = min(1.0, base_severity * 1.2) # 20% increase for admin

        if event.get('has_encoded') == 1:
            base_severity = min(1.0, base_severity * 1.3) # 30% increase for encoded

        if event.get('has_network') == 1:
            base_severity = min(1.0, base_severity * 1.1) # 10% increase for network

        # Convert to qualitative severity
        if base_severity > 0.85:
            return "High"
        elif base_severity > 0.6:
            return "Medium"
        else:
            return "Low"
    except Exception as e:
        logging.warning(f"Error calculating severity: {e}. Defaulting to Low.")
        return "Low"


def estimate_mitre_tactic(event):
    """Estimate MITRE ATT&CK tactic based on event characteristics"""
    # Simplified heuristic mapping - use a more robust mapping in production
    tactics = set()
    if event.get('has_encoded') == 1:
        tactics.add("Execution (T1059)") # PowerShell/Scripting
    if event.get('has_network') == 1:
        tactics.add("Command and Control (T1071)") # Application Layer Protocol
    if event.get('is_admin') == 1:
        # Could be many things, but often related to escalation or defense evasion
        tactics.add("Privilege Escalation (T1068)")
        tactics.add("Defense Evasion (T1070)")
    if 'powershell' in event.get('process_name', '').lower():
         tactics.add("Execution (T1059.001)") # PowerShell specific
    if 'cmd.exe' in event.get('process_name', '').lower():
         tactics.add("Execution (T1059.003)") # Windows Command Shell

    if not tactics:
        return "Execution" # Default guess

    return ", ".join(list(tactics))


def store_behavioral_anomalies(container, anomalies):
    """Store detected behavioral anomalies in Cosmos DB"""
    # Consider batching upserts for better performance if volume is high
    success_count = 0
    fail_count = 0
    for anomaly in anomalies:
        try:
            # Upsert item using 'id' field and partition key (assuming 'hostname')
            container.upsert_item(body=anomaly)
            success_count += 1
        except exceptions.CosmosHttpResponseError as e:
            logging.error(f"Error storing anomaly {anomaly.get('id')} in Cosmos DB: {e.status_code} - {e.message}")
            fail_count += 1
        except Exception as e:
            logging.error(f"Generic error storing anomaly {anomaly.get('id')} in Cosmos DB: {str(e)}")
            fail_count += 1
    logging.info(f"Finished storing anomalies. Success: {success_count}, Failed: {fail_count}")