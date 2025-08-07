This script takes in two files as arguments that contain comma-separated IP addresses or ranges in the formats X.X.X.X/X (CIDR) or X.X.X.X-X.X.X.X. 
It sanitizes the input and determines if the IPs in each file match. It will print the discrepancies or output all matching IPs. 
This is useful for scope validation for vulnerability scans or other assessments.

to install:

git clone https://www.github.com/ehrenandrus/IP-Comparison-Script.git
cd IP-Comparison-Script
python -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt

Usage:
python qva_IP_compare.py file1 file2
