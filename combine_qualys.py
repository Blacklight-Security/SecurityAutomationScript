import xml.etree.ElementTree as ET
import json
import argparse
from datetime import datetime

def parse_qualys_report(xml_file):
    """
    Parse a Qualys XML report and extract relevant information.
    """
    try:
        # Parse the XML file
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # Initialize the report structure
        report = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "source": "Qualys",
                "file": xml_file
            },
            "hosts": []
        }

        # Iterate through each host in the report
        for host in root.findall(".//IP"):
            host_data = {
                "ip": host.get("value"),
                "dns": host.get("name"),
                "information": {},
                "services": {},
                "vulnerabilities": []
            }

            # Extract host information
            for info in host.findall(".//INFOS/CAT"):
                cat_name = info.get("value")
                host_data["information"][cat_name] = {}
                for item in info.findall(".//INFO"):
                    info_title = item.find("TITLE").text.strip()
                    info_result = item.find("RESULT").text.strip() if item.find("RESULT") is not None else "N/A"
                    host_data["information"][cat_name][info_title] = info_result

            # Extract services
            for service in host.findall(".//SERVICES/CAT"):
                cat_name = service.get("value")
                host_data["services"][cat_name] = {}
                for item in service.findall(".//SERVICE"):
                    service_title = item.find("TITLE").text.strip()
                    service_result = item.find("RESULT").text.strip() if item.find("RESULT") is not None else "N/A"
                    host_data["services"][cat_name][service_title] = service_result

            # Extract vulnerabilities
            for vuln in host.findall(".//VULNS/CAT/VULN"):
                vuln_data = {
                    "qid": vuln.get("number"),
                    "title": vuln.find("TITLE").text.strip(),
                    "severity": int(vuln.get("severity")),
                    "cvss": 0.0,  # CVSS score is not present in the provided XML
                    "status": "Open",  # Status is not present in the provided XML
                    "diagnosis": vuln.find("DIAGNOSIS").text.strip() if vuln.find("DIAGNOSIS") is not None else "N/A",
                    "consequence": vuln.find("CONSEQUENCE").text.strip() if vuln.find("CONSEQUENCE") is not None else "N/A",
                    "solution": vuln.find("SOLUTION").text.strip() if vuln.find("SOLUTION") is not None else "N/A",
                    "cve_ids": [cve.find("ID").text.strip() for cve in vuln.findall(".//CVE_ID_LIST/CVE_ID")] if vuln.find(".//CVE_ID_LIST") is not None else []
                }
                host_data["vulnerabilities"].append(vuln_data)

            report["hosts"].append(host_data)

        return report

    except Exception as e:
        print(f"Error parsing Qualys report: {e}")
        return None

def combine_reports(security_scanner_report, qualys_report):
    """
    Combine the security scanner report with the Qualys report.
    """
    try:
        # Add Qualys data to the security scanner report
        security_scanner_report["qualys"] = qualys_report
        return security_scanner_report

    except Exception as e:
        print(f"Error combining reports: {e}")
        return None

def save_report(report, output_file):
    """
    Save the combined report to a JSON file.
    """
    try:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
        print(f"Report saved to {output_file}")
    except Exception as e:
        print(f"Error saving report: {e}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Combine Qualys report with security scanner report.")
    parser.add_argument("qualys_report", help="Path to the Qualys XML report")
    parser.add_argument("scanner_report", help="Path to the security scanner JSON report")
    parser.add_argument("-o", "--output", default="combined_report.json", help="Output file for the combined report")
    args = parser.parse_args()

    # Step 1: Parse the Qualys report
    qualys_report = parse_qualys_report(args.qualys_report)
    if not qualys_report:
        print("Failed to parse Qualys report.")
        exit(1)

    # Step 2: Load the security scanner report
    try:
        with open(args.scanner_report, "r") as f:
            security_scanner_report = json.load(f)
    except Exception as e:
        print(f"Error loading security scanner report: {e}")
        exit(1)

    # Step 3: Combine the reports
    combined_report = combine_reports(security_scanner_report, qualys_report)
    if not combined_report:
        print("Failed to combine reports.")
        exit(1)

    # Step 4: Save the combined report
    save_report(combined_report, args.output)

if __name__ == "__main__":
    main()