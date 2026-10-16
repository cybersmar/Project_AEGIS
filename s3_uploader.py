import boto3
import gzip
import shutil
import os
from datetime import datetime
from dotenv import load_dotenv

def backup_to_cloud():
    print("☁️ Initiating Secure AWS S3 Data Lake Backup...")
    
    # 1. Load the hidden secrets into memory
    # This pulls from the .env file but keeps them out of the source code!
    load_dotenv("/app/data/.env")
    
    bucket_name = os.getenv("AWS_S3_BUCKET_NAME")
    
    if not bucket_name:
        print("❌ CRITICAL ERROR: AWS_S3_BUCKET_NAME not found in .env file!")
        return

    local_file = "/app/data/cowrie_clustered.json"
    
    if not os.path.exists(local_file):
        print("Error: No clustered data found to backup.")
        return

    # 2. Compress the data
    today_date = datetime.now().strftime("%Y-%m-%d")
    zipped_filename = f"threat_intel_archive_{today_date}.json.gz"
    zipped_filepath = f"/app/data/{zipped_filename}"
    
    print(f"📦 Compressing logs into {zipped_filename}...")
    with open(local_file, 'rb') as f_in:
        with gzip.open(zipped_filepath, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # 3. Connect to the AWS Cloud
    # Boto3 automatically finds the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY loaded by dotenv!
    print("🔐 Authenticating with AWS IAM securely...")
    s3_client = boto3.client('s3')

    # 4. Upload the compressed archive
    print(f"🚀 Beaming data to S3 Bucket: {bucket_name}...")
    try:
        s3_client.upload_file(zipped_filepath, bucket_name, zipped_filename)
        print("✅ SUCCESS: Data securely archived in the AWS Cloud!")
    except Exception as e:
        print(f"❌ AWS Upload Failed: {e}")

if __name__ == "__main__":
    backup_to_cloud()