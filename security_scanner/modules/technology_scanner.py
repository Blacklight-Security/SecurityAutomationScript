import os
import re
import subprocess
from security_scanner.utils.logger import logger
from security_scanner.utils.helpers import ensure_installed

class TechnologyScanner:
    def __init__(self, config):
        self.config = config
        self.whatweb_installed = False
        self._verify_installation()

    def scan(self, domain, report):
        """Scan all subdomains for technologies using WhatWeb"""
        if not self.whatweb_installed:
            logger.error("WhatWeb not installed, skipping technology scan")
            return

        if not report.get("subdomains"):
            logger.warning("No subdomains found to scan")
            return

        technology_map = {}
        
        for subdomain in report["subdomains"]:
            try:
                logger.info(f"Scanning technologies for {subdomain}")
                tech_data = self._scan_subdomain(subdomain)
                if tech_data:
                    technology_map[subdomain] = tech_data
            except Exception as e:
                logger.error(f"Failed to scan {subdomain}: {e}")

        report["technologies"] = technology_map

    def _scan_subdomain(self, subdomain):
        """Scan a single subdomain using WhatWeb"""
        results = {}
        
        # Try both HTTP and HTTPS
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            try:
                output = self._run_whatweb(url)
                if output:
                    parsed = self._parse_whatweb_output(output)
                    if url in parsed:
                        results = parsed[url]
                        break  # Stop if successful
            except Exception as e:
                logger.debug(f"Protocol {protocol} failed for {subdomain}: {e}")
                continue

        return results if results else None

    def _run_whatweb(self, url):
        """Execute WhatWeb command"""
        try:
            user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
            result = subprocess.run(
                [
                    "whatweb",
                    "--color=never",
                    "-U", user_agent,
                    url
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except subprocess.TimeoutExpired:
            logger.debug(f"WhatWeb timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"WhatWeb execution error: {e}")
            return None

    def _parse_whatweb_output(self, output):
        """Parse raw WhatWeb output into structured data"""
        result = {}
        lines = output.strip().split("\n")
        
        for line in lines:
            # Extract URL and status
            url_match = re.match(r"^(http[s]?://[^\s]+)\s+\[(\d+)\s+([^\]]+)\]", line)
            if url_match:
                url = url_match.group(1)
                status_code = url_match.group(2)
                status_message = url_match.group(3)
                
                result[url] = {
                    "status_code": status_code,
                    "status_message": status_message,
                    "details": {}
                }
                
                # Extract details
                details = re.findall(r"([^,\[]+)\[([^\]]+)\]", line)
                for key, value in details:
                    result[url]["details"][key.strip()] = value.strip()
        
        return result

    def _verify_installation(self):
        """Check if WhatWeb is installed and install if necessary"""
        self.whatweb_installed = ensure_installed(
            command="whatweb",
            install_cmd=self._install_whatweb,
            prompt="WhatWeb is required for technology scanning. Install now?"
        )

    def _install_whatweb(self):
        """Install WhatWeb from source"""
        try:
            logger.info("Installing WhatWeb...")
            
            # Clone repository
            if not os.path.exists("WhatWeb"):
                subprocess.run(
                    ["git", "clone", "https://github.com/urbanadventurer/WhatWeb.git"],
                    check=True
                )
            
            # Install dependencies
            os.chdir("WhatWeb")
            subprocess.run(
                ["sudo", "gem", "install", "psych", "-v", "5.2.3", "--source", "https://rubygems.org/"],
                check=True
            )
            subprocess.run(["bundle", "install"], check=True)
            
            # Make executable and link
            subprocess.run(["chmod", "+x", "whatweb"], check=True)
            subprocess.run(
                ["sudo", "ln", "-s", f"{os.getcwd()}/whatweb", "/usr/local/bin/whatweb"],
                check=True
            )
            
            logger.info("WhatWeb installed successfully")
            return True
        except Exception as e:
            logger.error(f"WhatWeb installation failed: {e}")
            return False