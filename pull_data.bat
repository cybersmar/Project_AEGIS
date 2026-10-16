@echo off
echo ======================================== >> task_log.txt
echo %date% %time%: Starting Full SOC Data Science Pipeline... >> task_log.txt

echo Step 1: Extracting raw data from AWS... >> task_log.txt
docker exec python-etl python /app/data/extractor.py >> task_log.txt 2>&1

echo Step 2: Enriching data via AlienVault... >> task_log.txt
docker exec python-etl python /app/data/enricher.py >> task_log.txt 2>&1

echo Step 3: Running AI Anomaly Detection... >> task_log.txt
docker exec python-etl python /app/data/ml_detector.py >> task_log.txt 2>&1

echo Step 4: AI Botnet Profiling (K-Means)... >> task_log.txt
docker exec python-etl python /app/data/botnet_profiler.py >> task_log.txt 2>&1

echo Step 5: Pushing Entities to Neo4j Graph... >> task_log.txt
docker exec python-etl python /app/data/graph_builder.py >> task_log.txt 2>&1

echo %date% %time%: Pipeline finished successfully. >> task_log.txt