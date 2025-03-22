from requests.auth import HTTPBasicAuth
from security_scanner.utils.logger import logger

class EmailSecurityChecker:
    def __init__(self, api_client, config):
        self.api_client = api_client
        self.config = config
        
    def check(self, domain, report):
        logger.info(f"Assessing email security configuration for {domain}")
        try:
            headers = {"Authorization": f"{self.config['API_KEYS']['MXTOOLBOX']}", "Accept": "application/json"}
            for config in ["dmarc","spf"]:
                response = self.api_client.get(
                    f"https://mxtoolbox.com/api/v1/lookup/{config}/{domain}",
                    headers=headers
                )
                if response:
                    report["email_security"][config] = self.parse_mxtoolbox(response.json())
        except Exception as e:
            logger.error(f"Email security analysis failed: {e}")

    def parse_mxtoolbox(self, data):
        return {
            "Records": data.get("Records", []),
            "Errors": data.get("Errors", []),
            "Warnings": data.get("Warnings", []),
            "Failed": data.get("Failed", []),
            "DnsServiceProvider": data.get("DnsServiceProvider", None)
    }