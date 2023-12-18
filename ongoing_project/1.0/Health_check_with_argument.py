import os
import argparse
import subprocess
import tarfile
import re
import sys
import time
import re
import gzip
import datetime
from dateutil import parser
from plotly.graph_objs import Scatter, Layout
import plotly.offline as py
import logging
import pexpect

logging.basicConfig(filename='app.log', level=logging.INFO)
logger = logging.getLogger(__name__)


def show_spinner():
    spinner = ["|", "/", "-", "\\"]
    for _ in range(10):  # Number of iterations
        for char in spinner:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\b")


# Simulate a time-consuming operation
logger.info("Running a time-consuming operation:")
print("Running a time-consuming operation:")
show_spinner()

# Define the command-line argument parser
arg_parser = argparse.ArgumentParser(description="Datarake filename")
arg_parser.add_argument("datarake", help="Datarake file (e.g., .tgz)")

# Parse the command-line arguments
args = arg_parser.parse_args()

# Now you can access the parsed arguments
datarake_name = args.datarake
print(f'Saving information to {datarake_name}')
logger.info(f'Saving information to {datarake_name}')

all_data = []

# Define the directory where your files will be extracted (current directory)
output_directory = os.getcwd()


def save_output_without_for(output_file_path, datarake_files):
    with open(output_file_path, 'w') as out:
        for datarake_file in datarake_files:
            out.write(datarake_file)
        out.write("\n")


# Convert KB to GB

def kb_to_gb(KB):
    GB = KB / (1024 * 1024)
    return GB


# Function to check if the usage percentage is <= 60%
def is_usage_below_threshold(usage_percentage):
    return usage_percentage <= 60


# Define the directory where your files will be extracted
datarake_directory = os.path.splitext(datarake_name)[0]
output_file_path = os.path.join(f'{datarake_directory}.txt')
print(output_file_path)

# Check if the extraction directory already exists
if os.path.exists(datarake_directory):
    print("Skipping Extraction (Directory already exists)")
    logger.info("Skipping Extraction (Directory already exists)")

else:
    print(f"Extracting to {output_directory}")
    logger.info(f"Extracting to {output_directory}")
    # Extract the tarball to the output directory
    command = ["tar", "-xvf", datarake_name, "-C", output_directory]
    subprocess.run(command)


def convert_memory(mem):
    if not mem:
        return 0
    # if in GB convert to MB
    if 'g' in mem:
        mem = float(mem.split('g')[0]) * 1000
    # just numbers convert to MB from KB
    elif re.compile(r'[\d\.]*\d$').match(mem):
        mem = float(mem) / 1000
    else:
        print("Could not match memory in: {}".format(mem))
    return mem


datarake_directory = os.path.splitext(datarake_name)[0]
output_file_path = os.path.join(f'{datarake_directory}.txt')
print(output_file_path)

# Check Server Type HW or VM

# Define keywords to search for
virtualization_keywords = ['Virtual', 'VMware', 'Hypervisor', 'VirtualBox']

# Flag to track if virtualization was detected
is_virtual = False

with open(f'{datarake_directory}/tmp/datarake/dmidecode.txt',
          'r') \
        as source_file:
    dmidecode_lines = source_file.readlines()
    # Iterate through each line and check for virtualization keywords
    for line in dmidecode_lines:
        if any(keyword in line for keyword in virtualization_keywords):
            is_virtual = True
            break  # No need to continue searching if virtualization is detected

    # Determine and print the result
if is_virtual:
    result = 'Virtual Machine'
    all_data.append(result + '\n\n')
    # print(result)
    # save_output_without_for(output_file_path, result)
else:
    result = "Physical Server"
    all_data.append(result)
    # print(result)

# Read lscpu.txt

line_to_copy = None
with open(f'{datarake_directory}/tmp/datarake/lscpu.txt', 'r') \
        as source_file:
    lscpu_lines = source_file.readlines()
    if len(lscpu_lines) >= 5:  # Check if there are at least 5 lines
        line_to_copy = lscpu_lines[4]
        # Use regex to extract the desired format
        match = re.search(r'(\S+:)\s+(\S+)', line_to_copy)
        if match:
            formatted_line = f"{match.group(1)} {match.group(2)}"
            # print(formatted_line)
            all_data.append(formatted_line + '\n\n')
            # Append formatted_line to output_text.txt
            with open(output_file_path, 'a') as output_file:
                output_file.write(formatted_line + '\n\n')

# Read proc_meminfo.txt

with open(
        f'{datarake_directory}/tmp/datarake/proc_meminfo.txt',
        'r') \
        as source_file:
    mem_lines = source_file.readlines()
    first_line = mem_lines[0]
    # Parse the line to get the MemTotal value in KB
    mem_total_kb = int(first_line.split()[1])

    # Convert KB to GB using the function
    mem_total_gb = kb_to_gb(mem_total_kb)
    # print(f"RAM Size is: {mem_total_gb:.2f} GB")
    all_data.append(f"RAM Size is: {mem_total_gb:.2f} GB" + '\n\n')
    # save_output_without_for(output_file_path, f"RAM Size is: {mem_total_gb:.2f} GB")

# Server_ IP and Hostname
with open(f'{datarake_directory}/etc/hostname',
          'r') as source_file:
    hostname = source_file.readlines()
    cleaned_hostname = hostname[0].replace("'", "").replace("[", "").replace("]", "")
    # print(cleaned_hostname)
    # all_data.append(cleaned_hostname + '\n')

Ip_line_to_print = 9

with open(f'{datarake_directory}/tmp/datarake/ip-a.txt',
          'r') as source_file:
    ip_lines = source_file.readlines()

    if 0 < Ip_line_to_print <= len(ip_lines):
        line_to_print = ip_lines[Ip_line_to_print - 1]

        # Use a regular expression to find an IP address pattern in the line
        ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+)'
        match = re.search(ip_pattern, line_to_print)

        if match:
            ip_address = match.group(1)
            host_to_ip = f"{cleaned_hostname}: {ip_address}"
            # print(host_to_ip)
            all_data.append(host_to_ip + '\n\n')
            # save_output_without_for(output_file_path, host_to_ip)
        else:
            print("No IP address found in the line.")
            logger.info("No IP address found in the line.")
    else:
        print(f"Line {Ip_line_to_print} does not exist in the file.")
        logger.info(f"Line {Ip_line_to_print} does not exist in the file.")

# packet drop on Service interface

ifconfig_lines_to_print = 8
with open(f'{datarake_directory}/tmp/datarake/ifconfig.txt',
          'r') as source_file:
    ifconfig_lines = source_file.readlines()

    packet_drops_count = 0

    if 0 < ifconfig_lines_to_print <= len(ifconfig_lines):
        line_to_print = ifconfig_lines[ifconfig_lines_to_print - 3]

        if "dropped" in line_to_print:
            values = line_to_print.split()
            dropped_index = values.index("dropped")
            if dropped_index + 1 < len(values) and values[dropped_index + 1].isdigit():
                packet_drops_count = int(values[dropped_index + 1])

            if packet_drops_count > 0:
                eth0_drop = f"Packet drops were found on ETH0 {ip_address}. Drop Count: {packet_drops_count}"
                # print(eth0_drop)
                all_data.append(eth0_drop + '\n\n')
            else:
                no_eth0_drop = "No packet drops were found in ifconfig_lines."
                # print(no_eth0_drop)
                all_data.append(no_eth0_drop + '\n\n')

# Check Server disk Partition size
with open(
        f'{datarake_directory}/tmp/datarake/df-h.txt',
        'r') as source_file:
    disk_lines = source_file.readlines()
    # Skip the header line (first line)
    disk_lines = disk_lines[1:]

    # Initialize a flag to track if all partitions meet the criteria
    all_partitions_below_threshold = True

    # Parse and check each line
    for line in disk_lines:
        parts = line.split()
        partition = parts[0]
        usage_percentage = int(parts[-2].rstrip('%'))

        if not is_usage_below_threshold(usage_percentage):
            High_usage = f"Partition {partition} exceeds 60% usage ({usage_percentage}%), Please Investigate further"
            # print(High_usage)
            # save_output_without_for(output_file_path, High_usage)
            all_partitions_below_threshold = False

    # Print the result
    if all_partitions_below_threshold:
        Normal_usage = "All partitions are below or equal to 60% usage."
        # print(Normal_usage)
        all_data.append(Normal_usage + '\n\n')
        # save_output_without_for(output_file_path, Normal_usage)
    else:
        high_usage = "Some partitions exceed 60% usage."
        # print(high_usage)
        all_data.append(high_usage + '\n\n')
# Read PSM_CLIENT file

# Initialize status variables
dns_status = "DNS is not Running"
dhcp_status = "DHCP is not Running"
firewall_status = "Firewall is not Running"
ntp_status = "NTP is not Running"

# Open the file and read its lines
with open(f'{datarake_directory}/tmp/datarake'
          '/psmclient_extended.txt', 'r') as source_file:
    psm_lines = source_file.readlines()

    # Iterate through the lines
    for line in psm_lines:
        # Strip leading/trailing whitespace from the line
        line = line.strip()

        # Check if the line matches specific conditions
        if line == "node get-notify dns-enable=1":
            dns_status = "DNS is Running"
        elif line == "node get-notify dhcp-enable=1":
            dhcp_status = "DHCP is Running"
        elif line == "node get-notify firewall-enable=1":
            firewall_status = "Firewall is Running"
        elif line == "node get-notify ntp-enable=1":
            ntp_status = "Ntp is Running"
            service_status = [
                f"DNS Status: {dns_status}\n",
                f"DHCP Status: {dhcp_status}\n",
                f"Firewall Status: {firewall_status}\n",
                f"Ntp Status: {ntp_status}\n\n"
            ]
            # save_output(output_file_path, service_status)
            all_data.extend(service_status)

# Print the status of DNS and DHCP
# print(dns_status)
# print(dhcp_status)
# print(firewall_status)
# print(ntp_status)

# Query Looging Status

with open(f'{datarake_directory}/tmp/datarake'
          '/rndc_status.txt', 'r') as source_file:
    rndc_lines = source_file.readlines()

    for line in rndc_lines:
        if "query logging is ON" in line:
            query_logging_status = "Query logging is running, it's resource extensive and cause spikes in CPU and RAM"
            # print(query_logging_status)
            # save_output_without_for(output_file_path, query_logging_status)
            break  # Exit the loop as soon as we find the match
    else:
        # print("Query logging is not running")  # This will only execute if no match was found
        query_logging_status = "Query logging is not running"

    all_data.append(query_logging_status + '\n\n')
    # save_output_without_for(output_file_path, query_logging_status)

# NTP Sync-Information
ntp_lines_count = 0
ntp_good = True
with open(f'{datarake_directory}/tmp/datarake'
          '/ntpd.txt', 'r') as source_file:
    ntpd_lines = source_file.readlines()
    for i, line in enumerate(ntpd_lines):
        if i < 9:
            ntpd_status = (line.rstrip())
            # print(ntpd_status)
            all_data.append(ntpd_status + '\n')
            # save_output_without_for(output_file_path, ntpd_status)
        else:
            break

with open(f'{datarake_directory}/tmp/datarake'
          '/ntpd.txt', 'r') as source_file:
    ntpd_lines = source_file.readlines()

    # Initialize a flag to track NTP status
    ntp_low_latency = True

    # Iterate through lines, starting from the second line (skipping the header)
    for i, line in enumerate(ntpd_lines[2:8], start=1):
        columns = line.split()

        # Check if there are enough columns (at least 8) to access the "delay" value
        if len(columns) >= 8:
            try:
                delay = float(columns[7])
                remote_server = columns[0]

                if delay > 50:
                    ntp_good = False
                    high_latency = f"Remote server {remote_server} has high latency (Delay: {delay} ms)"
                    # print(high_latency)
                    all_data.append(high_latency + '\n')
                    # save_output_without_for(output_file_path, high_latency)
            except ValueError:
                print(f"Skipping line {i} due to invalid 'delay' value.")
                logger.info(f"Skipping line {i} due to invalid 'delay' value.")

    # Print the overall NTP status
    if ntp_good:
        ntp_good = "NTP is good."
        all_data.append(ntp_good + '\n\n')
    else:
        ntp_discl = "NTP Servers has high latency, Please Check with The customer."
        # print(ntp_discl)
        all_data.append(ntp_discl + '\n\n')

        # save_output_without_for(output_file_path, ntp_discl)
# XHA Status

# Initialize flags for each parameter

with open(f'{datarake_directory}/tmp/datarake'
          '/HAdiagnosis.txt', 'r') as source_file:
    XHA_lines = source_file.readlines()

    for i, line in enumerate(XHA_lines):
        if i < 10:
            XHA_status = line.rstrip()
            # print(XHA_status)
            # save_output_without_for(output_file_path, XHA_status)

# Check Server Patch

with open(f'{datarake_directory}/var/patch'
          '/patchDb.csv', 'r') as source_file:
    patch_lines = source_file.readlines()
    # Join all lines into a single string
    cleaned_patch_lines = ''.join(patch_lines)

    # Replace characters in the entire content
    cleaned_patch_lines = cleaned_patch_lines.replace("'", "").replace("[", "").replace("]", "")

    # Process the cleaned content
    patch_status = f"Server Patch level is : \n{cleaned_patch_lines}"
    # print(patch_status)
    all_data.append(patch_status + '\n\n')

# Check Namedmon and Perfstat


# List of service names to check
services_to_check = ["namedmon.py", "perfstats.sh", ]

# Read the ps -ef output file

with open(f'{datarake_directory}/tmp/datarake'
          '/ps_eLf.txt', 'r') as source_file:
    ps_ef_lines = source_file.readlines()

# Check the status of each service
for service in services_to_check:
    service_found = False
    for line in ps_ef_lines:
        if service in line:
            service_found = True
            break

    if service_found:
        status_services = f"{service} is running"
        # print(status_services)
    else:
        status_services = f"{service} is not running"
        # print(status_services)
    all_data.append(status_services + '\n\n')
# Read Resolve.conf

with open(f'{datarake_directory}/etc'
          '/resolv.conf', 'r') as source_file:
    resolve_lines = source_file.readlines()
    cleaned_resolve_lines = ''.join(resolve_lines)
    # Replace characters in the entire content
    cleaned_resolve_lines = cleaned_resolve_lines.replace("'", "").replace("[", "").replace("]", "")
    # print(cleaned_resolve_lines + "\n\n")
    all_data.append(cleaned_resolve_lines + '\n\n')

# Open the top.txt file for reading
with open(f'{datarake_directory}/tmp/datarake'
          '/top-b-n_1.txt', 'r') as top_file:
    top_lines = top_file.readlines()

# Search for the line containing uptime information
for line in top_lines:
    uptime_match = re.search(r'up (\d+) days', line)
    if uptime_match:
        days = int(uptime_match.group(1))
        server_uptime = f"Server Uptime: {days} days"
        # print(server_uptime)
        all_data.append(server_uptime + '\n\n')
        break  # Stop searching once the uptime is found

# Initialize dictionaries to store process information
cpu_processes = {}
memory_processes = {}

# Iterate through the lines starting from the process list and capture a specific number of lines
num_lines_to_capture = 10  # You can adjust this number as needed
for line in top_lines[7:]:
    if line.strip():
        columns = line.split()
        pid = columns[0]
        process_name = columns[11]
        cpu_usage = columns[8].rstrip('%')  # Remove '%' symbol
        memory_usage = columns[9]

        # Store process information in dictionaries
        cpu_processes[process_name] = (pid, cpu_usage)
        memory_processes[process_name] = (pid, memory_usage)

        # Break the loop when the desired number of lines is captured
        if len(cpu_processes) >= num_lines_to_capture:
            break

# Sort processes by CPU and memory usage
top_cpu_processes = sorted(cpu_processes.items(), key=lambda x: float(x[1][1]), reverse=True)
top_memory_processes = sorted(memory_processes.items(), key=lambda x: float(x[1][1]), reverse=True)

# Print the top CPU and memory processes
cpu_info = []  # Store CPU process information
mem_info = []
for process, (pid, cpu_usage) in top_cpu_processes[:5]:  # Capture CPU process information
    cpu_status = f"PID: {pid}, Process: {process}, CPU Usage: {cpu_usage}%"
    cpu_info.append(cpu_status)
# Print "Top CPU Processes:" once at the beginning
# print("Top CPU Processes:")

# Join the CPU process information with line breaks and print
formatted_cpu_info = '\n'.join(cpu_info)
# print(formatted_cpu_info)

# Append the formatted CPU process information to your 'all_data' list
all_data.append("Top CPU Processes:\n" + formatted_cpu_info + '\n\n')

for process, (pid, memory_usage) in top_memory_processes[:5]:  # Print the top 5 memory processes
    memory_status = f"PID: {pid}, Process: {process}, Memory Usage: {memory_usage}%"
    mem_info.append(memory_status)
# Print "Top Memory Processes:" once at the beginning
# print("Top Memory Processes:")

# Join the CPU process information with line breaks and print
formatted_mem_info = '\n'.join(mem_info)
# print(formatted_cpu_info)

# Append the formatted Memory process information to your 'all_data' list
all_data.append("Top Memory Processes:\n" + formatted_mem_info + '\n\n')

# Find ERRORS in CommandServer Log

with open(f'{datarake_directory}/var/log/commandServer.log', 'r') as top_file:
    commandServer_lines = top_file.readlines()
    tls_handshake_printed = False

    error_modifications = {
        "Exception while attempting to authenticate: Remote host closed connection during handshake": "INVESTIGATION "
                                                                                                      ": Due to TLS "
                                                                                                      "handshake "
                                                                                                      "Failure",
        "ERROR commandserver.CommandThread - Exception while attempting to authenticate: Received fatal alert: "
        "certificate_unknown": "INVESTIGATION: Known issue in <= 9.0.0",
        "ERROR ntp.NTPConfiguration - Problem setting NTP with IP address": "INVESTIGATION: Refer an Article "
                                                                            "000017449 on SalesForce",
        "ERROR dns.DNSDeployer - Cannot start DNS daemon: executeCommand() failed": "INVESTIGATION: Could be a "
                                                                                    "problem with named.conf, "
                                                                                    "like duplicate or wrong RAW "
                                                                                    "option",
        "ERROR dns.DynamicDeployer - Dynamic update batch (batch_size=1) failed: 'Refused'": "INVESTIGATION: Look at "
                                                                                             "PM-6891",
        "ERROR proteus.AbstractDeployServiceCommand - "
        "com.bluecatnetworks.adonis.server.commandserver.deployer.DeploymentException: Error when deploy config: "
        "/var/bluecat/deploy/DNS": "INVESTIGATION: Look at PM6891",
        # Add more error messages and their modifications here as needed
    }

    for error in commandServer_lines:
        if "ERROR" in error:
            for error_message, modification in error_modifications.items():
                if error_message in error:
                    error = error.replace(error_message, f"{error_message} ({modification})")

            # print(error)

            all_data.append(error)

save_output_without_for(output_file_path, all_data)
print("Operation completed!")
logger.info("Operation completed!")
print(datarake_directory)

root_password = "Nivedita@12345"
command = f"sudo rm -rf {datarake_directory}"

try:
    # Spawn a child process to run the command
    child = pexpect.spawn(command)

    # Expect the password prompt and send the root password
    child.expect("Password:")
    child.sendline(root_password)

    # Wait for the command to complete
    child.expect(pexpect.EOF)

    # Get the command's output and error
    output = child.before.decode()
    error = child.after.decode()

    if child.exitstatus == 0:
        print("Command ran successfully.")
        print("Output:", output)
    else:
        print("Command failed.")
        print("Error:", error)

except Exception as e:
    print("An error occurred:", str(e))
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
except FileNotFoundError as e:
    print(f"Error: {e}")


