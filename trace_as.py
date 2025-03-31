import subprocess
import re
import requests
import sys
import ipaddress

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private or ip.startswith("100.64.")


def run_traceroute(target):
    try:
        result = subprocess.run(
            ["traceroute", "-n", target], capture_output=True, text=True
        )
        return result.stdout
    except Exception as e:
        print(f"Error while preforming traceroute: {e}")
        return


def find_ips(tracert_result):
    return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', tracert_result)


def get_ip_info(ip):
    try:
        if is_private_ip(ip):
            return "Private", "Local network", "N/A"

        response = requests.get(f"http://ipwho.is/{ip}")
        data = response.json()

        if not isinstance(data, dict) or not data.get("success"):
            return "Unknown", "Unknown", "Unknown"

        asn = data["connection"]["asn"] if "connection" in data and "asn" in data["connection"] else "N/A"
        country = data["country"] if "country" in data else "N/A"
        provider = data["connection"]["isp"] if "connection" in data and "isp" in data["connection"] else "N/A"

        return asn, country, provider

    except Exception as e:
        print(f"Fail getting info about {ip}: {e}")
        return "Error", "Error", "Error"


def main():

    target = sys.argv[1]
    output = run_traceroute(target)
    ips = find_ips(output)

    print("№ | IP             | AS     | Country         | Provider")
    print("-" * 70)
    for i, ip in enumerate(ips, start=1):
        asn, country, provider = get_ip_info(ip)
        print(f"{i:2} | {ip:13} | {asn:6} | {country:13} | {provider}")


if __name__ == "__main__":
    main()
