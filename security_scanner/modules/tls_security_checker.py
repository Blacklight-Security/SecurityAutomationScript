import time
from requests.auth import HTTPBasicAuth
from security_scanner.utils.logger import logger


class TlsSecurityChecker:
    def __init__(self, api_client, config):
        self.api_client = api_client
        self.config = config
        
    def check(self, domain, report):
        """Check TLS configuration for all subdomains using SSL Labs API."""
        tls_results = {}
        pending_subdomains = report.get("subdomains")
        logger.info(f"Checking TLS config for {pending_subdomains}")

        # Initial request for all subdomains
        for subdomain in pending_subdomains:
            self.api_client.get(f"https://api.ssllabs.com/api/v3/analyze?host={subdomain}")

        # Poll until all subdomains are ready
        while pending_subdomains:
            time.sleep(10)  # Wait 10 seconds between checks
            for subdomain in list(pending_subdomains):  # Use list to avoid modifying set during iteration
                response = self.api_client.get(f"https://api.ssllabs.com/api/v3/analyze?host={subdomain}")
                if response:
                    data = response.json()
                    endpoints = data.get("endpoints", [])
                    if endpoints and endpoints[0].get("statusMessage") != "In progress":
                        # Extract the first endpoint's results
                        first_endpoint = endpoints[0]
                        tls_results[subdomain] = {
                            "grade": first_endpoint.get("grade"),
                            "warnings": first_endpoint.get("hasWarnings", False),
                            "status": first_endpoint.get("statusMessage", False)
                        }
                        pending_subdomains.remove(subdomain)

        # Add TLS results to the report
        report["tls_config"] = tls_results