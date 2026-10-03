#!/bin/bash

# Ask the user for the number of iterations to run
echo "Enter the number of iterations to execute:"
read iterations

# Define commands to execute
scan_command="sudo zmap --bandwidth=10M --target-port=443 --max-targets=1000 --output-file=ips.csv" # Scan port 443 and save IPs to csv
python_command="python3 ./certificate_download.py" # Download SSL certificates from IP list
delete_command="rm -f ./ips.csv" # Delete csv to avoid duplication in loops

# Run commands in loop
for ((i=1; i<=$iterations; i++)); do
    echo "Iteration $i"
    $scan_command
    $python_command
    $delete_command
done

echo "Script completed $iterations iterations successfully"