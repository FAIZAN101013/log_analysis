import re
import csv
from collections import defaultdict

# Function to read and process the log file
def process_log_file(log_file_path, threshold=10):
    ip_requests = defaultdict(int)
    endpoint_hits = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regex patterns for extracting data
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # To find IPs
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD) ([^\s]+)'  # To find endpoints
    failed_login_pattern = r'401'  # To find failed logins

    with open(log_file_path, 'r') as file:
        for line in file:
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_hits[endpoint] += 1

            if re.search(failed_login_pattern, line):
                if ip_match:
                    failed_logins[ip] += 1

    most_accessed_endpoint = max(endpoint_hits.items(), key=lambda x: x[1], default=("", 0))
    suspicious_ips = {}
    for ip, count in failed_logins.items():
        if count > threshold:
            suspicious_ips[ip] = count

    return ip_requests, most_accessed_endpoint, suspicious_ips

# Function to save the data into a CSV file
def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious IPs
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main script
if __name__ == "__main__":
    log_file_path = "sample.log"
    output_file = "log_analysis_results.csv"

    ip_requests, most_accessed_endpoint, suspicious_ips = process_log_file(log_file_path)

    # Print results to the console
    print("Requests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]}: {most_accessed_endpoint[1]}")

    print("\nSuspicious IPs:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count}")

    # Save the results to a CSV file
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file)
    print(f"Results saved to {output_file}")
