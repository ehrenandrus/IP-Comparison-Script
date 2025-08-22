import sys
import re
import ipaddress
from netaddr import iter_nmap_range
import os

#to do more error checking
#figure out a way to accomodate x.x.x.x - x.x.x.x and not just x.x.x.x-x.x.x.x The issue is that I split on spaces or commas

IP_REG=r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
IP_RANGE=fr"{IP_REG}-{IP_REG}"
#IP_CIDR=r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
array_file1 = []
array_file2 = []


#assumes IP data are separated by commas or separated with newlines or both
#strip white space
def sanitize_data(line):
    return [item.strip(' ') for item in re.split(r'[ ,]+', line)]


# individually check if its / or - or single IP and call relevant function to handle
def parse(item, file_num):
    if "/" in item:
        # handle expansion function
        expand_cidr(item, file_num)
    elif "-" in item:
        # handle expansion function
        expand_range(item, file_num)
    elif re.match(IP_REG, item): #if reg IP
        #add to list
        add_single_IP(item, file_num)
    else:
        print(f"Incorrect IP range/address format: {item}")
        sys.exit(1)


def expand_cidr(item, file_num):
    network = ipaddress.ip_network(f"{item}", strict=False) #strict=false for if host bit set
    for ip in network:
        if file_num == 1:
            array_file1.append(str(ip))
        else:
            array_file2.append(str(ip))


def expand_range(item, file_num):
    ips = [ip.strip() for ip in item.split("-")]
    start = ipaddress.IPv4Address(ips[0])
    stop = ipaddress.IPv4Address(ips[1])
    current_ip = int(start)
    stop_ip = int(stop)

    while current_ip <= stop_ip:
        if file_num == 1:
            array_file1.append(str(ipaddress.IPv4Address(current_ip)))
        else:
            array_file2.append(str(ipaddress.IPv4Address(current_ip)))
        current_ip += 1

def add_single_IP(item, file_num):
    if file_num == 1:
        array_file1.append(item)
    else:
        array_file2.append(item)

#maybe modify with a separate function for printing output, passing in diff_in_arrays
def sort_and_compare():
    print(array_file1)
    print(array_file2)
    set1 = set(array_file1)
    set2 = set(array_file2)

    #create .gitignore directory
    out = "output"
    try:
        os.mkdir(out)
        print(f"Creating directory {out} for output files to avoid accidental pushes to repo.")
    except FileExistsError:
        print(f"{out} directory already exists. Saving output files there to avoid accidental pushes to repo.")

    #find unique IPs to file1
    diff_in_array1 = list(set1 - set2)
    with open(f"{out}/unique_ips_in_file1.txt", "w") as f:
        print(f"{', '.join(diff_in_array1)}", file=f)

    #find unique IPs to file2
    diff_in_array2 = list(set2 - set1)
    with open(f"{out}/unique_ips_in_file2.txt", "w") as f:
        print(f"{', '.join(diff_in_array2)}", file=f)

    #print unique IPs or print everything matches
    if len(diff_in_array2) != 0 or len(diff_in_array1) != 0:
        print(f"These are unique to file 1:\n{diff_in_array1}")
        print(f"***************************")
        print(f"***************************")
        print(f"These are unique to file 2:\n{diff_in_array2}")
        print("Output printed to unique* files.")
    else:
        sorted1 = sorted(set1)
        sorted2 = sorted(set2)
        #print formated matches
        with open(f"{out}/match.txt", "w") as f:
            for i in range(len(sorted1)):
                print(f"{sorted1[i]}     {sorted2[i]:<20}", file=f)
                print(f"{sorted1[i]}     {sorted2[i]:<20}")
        print(f"Everything Matches!! Output printed to match.txt.")

def main():
    files = []
    if len(sys.argv) == 3:
        files.append(sys.argv[1])
        files.append(sys.argv[2])
    else:
        print(f"Usage: ./this_script fileToCompare1 fileToCompare2")
        sys.exit(1)

    # read files
    for i in range(len(sys.argv) - 1):
        try:
            with open(files[i], "r") as f:
                for line in f:
                    if not line.isspace():
                        # parse data to arrays and strip white spaces
                        arr = sanitize_data(line)
                        for item in arr:
                            parse(item.strip(), i + 1)
        except FileNotFoundError:
            print(f"{files[i]} does not exist. Please choose existing file.")

    sort_and_compare()


if __name__ == "__main__":
    main()



