import os
import random
import time
from playwright.sync_api import sync_playwright
from googlesearch import search
from security_scanner.utils.helpers import add_unique_values
from security_scanner.utils.logger import logger

class WebCrawler:
    def __init__(self, config):
        self.config = config

    def google_dorking(self, domain, report):
        DORKS = [
            "filetype:pdf",
            "filetype:xls OR filetype:xlsx",
            '"index of /config"',
            '"index of /.git"',
            '"index of /.svn"',
            '"index of /logs"',
            'intitle:"Login" OR inurl:"login"',
            'inurl:"admin"',
            "filetype:sql",
            '"index of /"',
            '"index of /backup"',
            '"confidential" OR "private" OR "sensitive"',
            '"metadata"',
            '"index of /database"',
            '"index of /user"',
            '"index of /account"',
            'inurl:wp-content',
            'inurl:wp-includes',
            f'"site:{domain} inurl:phpinfo.php"',
            f'"site:{domain} inurl:php.ini"',
            '"allintext:password filetype:log"',
            '"allintext:username filetype:log"',
            '"intitle:index.of bash_history"',
            '"intitle:index.of mysql_history"',
            '"intitle:index.of config db"',
            '"intitle:index.of backup"',
            'intext:"sql_dump" filetype:sql',
            '"backup filetype:bak"',
            f'"site:{domain} intitle:index.of /admin"',
            f'"site:{domain} intitle:index.of /private"',
            f'"site:{domain} intitle:index.of /ftp"',
            f'"site:{domain} intitle:index.of /passwords"'
        ]
        logger.info(f"Performing Google dorking for {domain}")
        try:
            for dork in DORKS:
                query = f"site:{domain} {dork}"
                results = list(search(query, num_results=10, unique=True, sleep_interval=5))
                if results:
                    add_unique_values(report, "sensitive_info", results)
                time.sleep(random.randint(5, 15))
        except Exception as e:
            logger.error(f"Google dorking failed: {e}")

    def capture_screenshots(self, domain, report):
        logger.info(f"Capturing screenshots for {domain}")
        screenshot_dir = f"scan_results_{report['metadata']['target']}/screenshots_{domain}"
        os.makedirs(screenshot_dir, exist_ok=True)
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            
            for url in report["subdomains"] + report["sensitive_info"]:
                try:
                    page.goto(f"https://{url}", wait_until="domcontentloaded")
                    screenshot_path = os.path.join(screenshot_dir, f"{url.replace('://', '_')}.png")
                    page.screenshot(path=screenshot_path, full_page=True)
                    report["screenshots"].append(screenshot_path)
                except Exception as e:
                    logger.error(f"Failed to capture {url}: {e}")
            browser.close()