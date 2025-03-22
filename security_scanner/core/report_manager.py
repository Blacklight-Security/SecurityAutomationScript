from datetime import datetime
import json
import os


class ReportManager:
    @staticmethod
    def init_report(domain, company_name):
        # Create scan rsults directory if it doesn't exist
        scan_dir = f"scan_results_{domain}"
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
        return {
            "metadata": {
                "target": domain,
                "company": company_name,
                "scan_date": datetime.now().isoformat()
            },
            "dns_records": {},
            "subdomains": [],
            "subipmap": {},
            "ip_addresses": [],
            "vulnerabilities": [],
            "services": [],
            "email_security": {},
            "darkweb": {},
            "sensitive_info": [],
            "credentials": [],
            "screenshots": [],
            "technologies": {}
        }

    @staticmethod
    def add_unique_values(report, descriptor, values):
        existing = set(report.get(descriptor, []))
        report[descriptor] = list(existing.union(set(values)))

    @staticmethod
    def save_report(report):
        filename = f"scan_results_{report['metadata']['target']}/security_report_{report['metadata']['target']}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)