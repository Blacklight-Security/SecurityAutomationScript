import shodan
from security_scanner.utils.logger import logger

class ThirdPartyIntegrations:
    @staticmethod
    def shodan_scan(domain, config, report):
        try:
            logger.info(f"Running Shodan scan for {domain}")
            api = shodan.Shodan(config['API_KEYS']['SHODAN'])
            results = api.search(f"hostname:{domain}")
            report["ip_addresses"] = [item['ip_str'] for item in results['matches']]
            report["services"] = results['matches']
        except Exception as e:
            logger.error(f"Shodan scan failed: {e}")