import requests
from security_scanner.utils.logger import logger

class QualysIntegration:
    def __init__(self, config):
        self.config = config
        self.session = None

    def login(self):
        try:
            response = requests.post(
                "https://qualysapi.qualys.com/api/2.0/fo/session/",
                data={
                    "action": "login",
                    "username": self.config['API_KEYS']['QUALYS_USERNAME'],
                    "password": self.config['API_KEYS']['QUALYS_PASSWORD']
                }
            )
            self.session = response.cookies
            return True
        except Exception as e:
            logger.error(f"Qualys login failed: {e}")
            return False

    def run_scan(self, domain):
        if self.login():
            try:
                response = requests.post(
                    "https://qualysapi.qualys.com/api/2.0/fo/scan/",
                    cookies=self.session,
                    data={
                        "action": "launch",
                        "scan_title": f"Scan {domain}",
                        "ip": domain
                    }
                )
                return response.text
            except Exception as e:
                logger.error(f"Qualys scan failed: {e}")
        return None