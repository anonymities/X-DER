#!/bin/bash

# Ask the user for the number of executions
echo "Enter the number of executions:"
read iterations

# Specify commands to execute
scan_command="sudo zmap --bandwidth=10M --target-port=443 --max-targets=1000 --output-file=ips.csv" #zmap scans port and saves ips to csv file
python_command="python3 ./certificate_download.py" #py script to download certificates via ips in csv
delete_command="rm -f ./ips.csv" #delete csv (loop execution, unsure if it overwrites or appends, so delete and re-scan)

# Execute commands in loop
for ((i=1; i<=$iterations; i++)); do
    echo "Iteration $i"
    $scan_command  # execute scan command
    $python_command  # execute Python script
    $delete_command  # delete file
done

echo "Script completed $iterations executions"

# About 50 times can download around 1000 certificates, number of open ports varies, download may also time out occasionally