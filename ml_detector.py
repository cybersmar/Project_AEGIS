import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
import os

def run_ai_detector():
    input_file = "/app/data/cowrie_enriched.json"
    output_file = "/app/data/cowrie_ml.json"
    
    print("🧠 Initializing Machine Learning Anomaly Detector...")
    
    if not os.path.exists(input_file):
        print("No enriched data found. Exiting.")
        return

    # 1. Load the data into memory
    raw_logs = []
    with open(input_file, "r") as f:
        for line in f:
            try:
                raw_logs.append(json.loads(line.strip()))
            except:
                continue
                
    if not raw_logs:
        print("File is empty.")
        return

    # 2. Feature Engineering: Turn text into math for the AI
    df = pd.DataFrame(raw_logs)
    features = []
    
    for index, row in df.iterrows():
        # Feature A: Hour of the attack (0-23)
        try:
            timestamp = datetime.strptime(row.get('timestamp')[:19], "%Y-%m-%dT%H:%M:%S")
            hour = timestamp.hour
        except:
            hour = 12
            
        # Feature B: Password complexity (length)
        pwd = str(row.get('password', ''))
        pwd_len = len(pwd)
        
        # Feature C: Known Threat Score (from AlienVault)
        pulse_count = int(row.get('otx_pulse_count', 0))
        
        features.append([hour, pwd_len, pulse_count])

    feature_df = pd.DataFrame(features, columns=['hour', 'pwd_len', 'pulse_count'])

    # 3. Train the Isolation Forest AI
    # contamination=0.05 means we assume the top 5% weirdest events are "Anomalies"
    print("🤖 Training Isolation Forest model on historical data...")
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(feature_df)

    # 4. Predict! (-1 means Anomaly, 1 means Normal)
    predictions = model.predict(feature_df)
    
    # 5. Append the AI's verdict back to the logs
    print("🔍 Classifying events...")
    for i, log in enumerate(raw_logs):
        if predictions[i] == -1:
            log['ai_anomaly_flag'] = "TRUE"
            log['ai_risk_score'] = 99
        else:
            log['ai_anomaly_flag'] = "FALSE"
            log['ai_risk_score'] = 10

    # 6. Save the final, AI-scored dataset
    with open(output_file, "w") as f:
        for log in raw_logs:
            f.write(json.dumps(log) + "\n")

    print(f"✅ AI Analysis Complete! {list(predictions).count(-1)} anomalies detected out of {len(raw_logs)} events. Saved to cowrie_ml.json")

if __name__ == "__main__":
    run_ai_detector()