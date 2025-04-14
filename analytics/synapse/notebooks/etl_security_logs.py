# Example PySpark Notebook for ETL in Synapse

from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *

# Initialize Spark Session (adjust config as needed)
spark = SparkSession.builder.appName("SecurityLogETL").getOrCreate()

# Define ADLS paths (replace with your actual linked service/account details)
# Assumes ASA output is partitioned by date/time in JSON Lines format
adls_base_path = "abfss://raw-logs@<your_adls_account_name>.dfs.core.windows.net/logs"
date_path = "yyyy/MM/dd/HH" # Matches ASA output path pattern
output_path_parquet = "abfss://processed-data@<your_adls_account_name>.dfs.core.windows.net/security_logs_parquet"

# --- 1. Load Raw Data --- 
# Load data for a specific time range (e.g., last day)
# In production, you would parameterize the date/time or use Delta Lake time travel
print(f"Loading data from: {adls_base_path}/{date_path}...")
# This path structure depends heavily on how ASA writes the data
df_raw = spark.read.json(f"{adls_base_path}/2024/01/01/*") # Example: Load one hour
# Or load multiple paths: spark.read.json([f"{adls_base_path}/2024/01/01/10", f"{adls_base_path}/2024/01/01/11"])

print(f"Raw count: {df_raw.count()}")
df_raw.printSchema()
df_raw.show(5, truncate=False)

# --- 2. Basic Transformations & Cleaning --- 
# Flatten nested structures, cast data types, rename columns, etc.
# This depends heavily on your specific log schema
print("Applying transformations...")

df_transformed = df_raw\
    .withColumn("eventTime", to_timestamp(col("EventTime"))) # Example: Cast timestamp
    .withColumn("eventSource", lit("EventHubStream")) # Add source column
    # .withColumn("parsedData", from_json(col("OriginalMessage"), someSchema)) # Example: Parse nested JSON
    .drop("EventProcessedUtcTime", "PartitionId", "EventEnqueuedUtcTime") # Drop ASA metadata

# --- 3. Join with External Data (Example: Asset Info) --- 
# Assume asset_info_df is loaded from another source (CSV, Parquet, DB)
# asset_info_df = spark.read.parquet("abfss://processed-data@.../asset_info")
#
# print("Joining with asset info...")
# df_joined = df_transformed.join(
#     asset_info_df,
#     df_transformed["Computer"] == asset_info_df["hostname"], # Example join condition
#     "left_outer"
# )

# Use df_transformed if no join is performed initially
df_final = df_transformed

# --- 4. Write Processed Data to Parquet/Delta Lake --- 
print(f"Writing processed data to: {output_path_parquet}")
df_final.write\
    .mode("append") # Use append or overwrite based on your strategy
    .partitionBy("eventSource", "eventTime") # Example partitioning
    .parquet(output_path_parquet)
    # Or use Delta Lake for ACID transactions, time travel etc.
    # .format("delta").save(output_path_delta)

print("ETL Job Complete.")

# Stop Spark Session
spark.stop() 