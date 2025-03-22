import socket
from security_scanner.utils.helpers import add_unique_values
from security_scanner.utils.logger import logger

class DNSAnalyzer:
    def __init__(self, api_client, config):
        self.api_client = api_client
        self.config = config
        self.queries = [self._query_virustotal, self._query_crtsh] 

    def get_dns_info(self, domain, report):
        try:
            for query in self.queries:
                subdomains = query(domain)
                add_unique_values(report, "subdomains", subdomains)
            subdomains = self._query_security_trails(domain, report)
            add_unique_values(report, "subdomains", subdomains)
            self._resolve_subdomains(domain, report)
            report['dns_resolved'] = True
        except Exception as e:
            logger.error(f"DNS analysis failed: {e}")

    def _resolve_subdomains(self, domain, report):
        try:
            for subdomain in report.get("subdomains", []):
                ips = {res[4][0] for res in socket.getaddrinfo(subdomain, None)}
                report["subipmap"][subdomain] = list(ips)
                add_unique_values(report, "ip_addresses", ips)
        except socket.gaierror as e:
            logger.error(f"DNS resolution error: {e}")

    def _query_security_trails(self, domain, report):
        try:
            # Query DNS info
            headers = {"APIKEY": self.config['API_KEYS']['SECURITYTRAILS']}
            response = self.api_client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers=headers
            )
            if response:
                report["dns_records"] = response.json()

            # Query subdomains
            response = self.api_client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers=headers
            )
            if response and response.status_code == 200:
                subdomains = set(item+domain for item in response.json()["subdomains"])
                return subdomains
        except Exception as e:
            logger.error(f"SecurityTrails error: {e}")
        return set()


    def _query_crtsh(self, domain):
        """Fallback 1: Certificate Transparency logs (crt.sh)"""
        try:
            response = self.api_client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10
            )
            if response and response.status_code == 200:
                subdomains = set()
                for item in response.json():
                    # Split the name_value field by newlines
                    names = item.get("name_value", "").lower().strip().split("\n")
                    for name in names:
                        # Filter out invalid entries (e.g., email addresses and wildcards)
                        if (name.endswith(f".{domain}") or name == domain) and "*" not in name:
                            subdomains.add(name)
                logger.info(f"Found {len(subdomains)} subdomains from crt.sh")
                logger.debug(subdomains)
                return subdomains
        except Exception as e:
            logger.debug(f"crt.sh failed: {str(e)}")
        return set()


    def _query_virustotal(self, domain):
        """Fallback 2: VirusTotal API"""
        response = "test"
        try:
            headers = {"x-apikey": self.config['API_KEYS']['VIRUSTOTAL']}
            response = self.api_client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                headers=headers
            )
            # logger.debug(response.text)
            if response and response.status_code == 200:
                logger.info(f"Found {len(response.json().get('data', []))} subdomains from VirusTotal")
                subs = set(item["id"] for item in response.json().get("data", []))
                logger.debug(subs)
                return subs
        except Exception as e:
            logger.error(f"VirusTotal failed: {str(e)}")
            logger.debug(response.text)
        return set()