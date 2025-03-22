from bs4 import BeautifulSoup
from security_scanner.utils.logger import logger

class DarkwebChecker:
    def __init__(self, api_client):
        self.api_client = api_client
        
    def check(self, domain, report):
        logger.info(f"Checking dark web mentions for {domain}")
        try:
            response = self.api_client.get(f"https://ahmia.fi/search/?q={domain}")
            if response:
                soup = BeautifulSoup(response.text, "html.parser")
                results = []
                for result in soup.select("li.result"):
                    title = result.select_one("h4 a").text.strip()
                    url = result.select_one("cite").text.strip()
                    description = result.select_one("p").text.strip()
                    results.append({"title": title, "url": url, "description": description})
                report["darkweb"] = results
        except Exception as e:
            logger.error(f"Dark web check failed: {e}")