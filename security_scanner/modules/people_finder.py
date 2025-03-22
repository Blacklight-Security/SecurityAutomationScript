from requests.auth import HTTPBasicAuth
from security_scanner.utils.logger import logger

class PeopleFinder:
    def __init__(self, api_client, config):
        self.api_client = api_client
        self.config = config
        
    def find(self, domain, report):
        logger.info(f"Searching for people associated with {domain}")
        try:
            headers = {"Accept": "application/json"}
            response = self.api_client.get(
                f"https://api.dehashed.com/search?query=domain:{domain}",
                auth=HTTPBasicAuth(
                    self.config['API_KEYS']['DEHASHED_EMAIL'],
                    self.config['API_KEYS']['DEHASHED']
                ), headers=headers
            )
            if response:
                report["credentials"] = response.json().get("entries", [])
        except Exception as e:
            logger.error(f"People search failed: {e}")