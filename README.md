This script takes in two files as arguments that contain comma-separated or line-by-line IP addresses or ranges in the formats X.X.X.X/X (CIDR) or X.X.X.X-X.X.X.X. 
It cleans the input and determines if the IPs in each file match. It will print the discrepancies or output all matching IPs. 
This is useful for scope validation for vulnerability scans or other assessments.

to install:

git clone https://www.github.com/ehrenandrus/IP-Comparison-Script.git
cd IP-Comparison-Script
./setup.sh  # or setup.bat on Windows


Usage:

#in repo directory
#activate virtual environment first (activated during setup)
source venv/bin/activate #Windows cmd -> call venv\Scripts\activate
python qva_IP_compare.py file1 file2

#powershell
.\venv\Scripts\python.exe qva_IP_compare.py file1 file2

deactivate #when done deactivate virtual environment
