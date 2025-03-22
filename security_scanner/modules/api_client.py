import requests
import time
from threading import Semaphore
from security_scanner.utils.logger import logger

class APIClient:
    def __init__(self, config):
        self.config = config
        self.semaphore = Semaphore(int(config['SETTINGS']['THREADS']))
        self.timeout = int(config['SETTINGS']['TIMEOUT'])

    def get(self, url, headers=None, auth=None, params=None, retries=3, timeout=None):
        with self.semaphore:
            for attempt in range(retries):
                try:
                    logger.debug(f"GET: {url}")
                    response = requests.get(
                        url,
                        headers=headers,
                        auth=auth,
                        params=params,
                        timeout=self.timeout
                    )
                    # logger.debug(response.text)
                    self._handle_response(response)
                    return response
                except requests.exceptions.RequestException as e:
                    self._handle_retry(attempt, retries, e)
            return None

    def post(self, url, headers=None, auth=None, json=None, retries=3, timeout=None):
        with self.semaphore:
            for attempt in range(retries):
                try:
                    logger.debug(f"POST: {url}")
                    response = requests.post(
                        url,
                        headers=headers,
                        auth=auth,
                        json=json,
                        timeout=self.timeout
                    )
                    # logger.debug(response.text)
                    self._handle_response(response)
                    return response
                except requests.exceptions.RequestException as e:
                    self._handle_retry(attempt, retries, e)
            return None

    def _handle_response(self, response):
        logger.debug(f"Status: {response.status_code}")
        if response.status_code != 200:
            logger.debug(f"Response: {response.text}")
        response.raise_for_status()

    def _handle_retry(self, attempt, max_retries, error):
        if attempt == max_retries - 1:
            raise error
        logger.debug(f"Retrying ({attempt+1}/{max_retries})")
        time.sleep(2 ** attempt)