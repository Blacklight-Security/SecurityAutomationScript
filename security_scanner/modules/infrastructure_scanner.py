import os
import sys
import xml.etree.ElementTree as ET
import subprocess
from security_scanner.utils.logger import logger
from security_scanner.utils.helpers import ensure_installed

class InfrastructureScanner:
    def __init__(self, config):
        self.config = config
        self.rustscan_installed = False
        self.nmap_installed = False
        self._verify_dependencies()

    def scan(self, domain, report):
        """Main infrastructure scanning entry point"""
        if not all([self.rustscan_installed, self.nmap_installed]):
            logger.error("Missing dependencies, skipping infrastructure scan")
            return

        scan_dir = f"scan_results_{domain}"
        os.makedirs(scan_dir, exist_ok=True)
        
        report["port_scan"] = {}
        report["ipportmap"] = {}

        for subdomain in report.get("subdomains", []):
            try:
                logger.info(f"Scanning {subdomain} infrastructure")
                scan_data = self._run_scan(subdomain, scan_dir)
                if scan_data:
                    report["port_scan"][subdomain] = scan_data["results"]
                    report["ipportmap"].update(scan_data["ipportmap"])
            except Exception as e:
                logger.error(f"Infrastructure scan failed for {subdomain}: {e}")

    def _verify_dependencies(self):
        """Verify and install required dependencies"""
        self.rustscan_installed = ensure_installed(
            command="rustscan",
            install_cmd=self._install_rustscan,
            prompt="RustScan required for port scanning. Install now?"
        )
        
        self.nmap_installed = ensure_installed(
            command="nmap",
            install_cmd=self._install_nmap,
            prompt="Nmap required for port scanning. Install now?"
        )

    def _install_rustscan(self):
        """Install RustScan and its dependencies"""
        try:
            if not ensure_installed("cargo", self._install_rust):
                return False

            logger.info("Installing RustScan...")
            subprocess.run(["cargo", "install", "rustscan"], check=True)
            return True
        except Exception as e:
            logger.error(f"RustScan installation failed: {e}")
            return False

    def _install_rust(self):
        """Install Rust toolchain"""
        try:
            logger.info("Installing Rust...")
            subprocess.run(
                ["curl", "--proto", "=https", "--tlsv1.2", "-sSf", "https://sh.rustup.rs", "-o", "rustup.sh"],
                check=True
            )
            subprocess.run(["sh", "rustup.sh", "-y"], check=True)
            return True
        except Exception as e:
            logger.error(f"Rust installation failed: {e}")
            return False

    def _install_nmap(self):
        """Install Nmap"""
        try:
            logger.info("Installing Nmap...")
            if sys.platform == "linux":
                subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
            elif sys.platform == "darwin":
                subprocess.run(["brew", "install", "nmap"], check=True)
            else:
                logger.error("Unsupported OS for Nmap installation")
                return False
            return True
        except Exception as e:
            logger.error(f"Nmap installation failed: {e}")
            return False

    def _run_scan(self, target, output_dir):
        """Execute RustScan/Nmap combined scan"""
        try:
            xml_file = os.path.join(output_dir, f"{target}_nmap_scan.xml")
            
            logger.debug(f"Running RustScan/Nmap scan on {target}")
            result = subprocess.run(
                [
                    "rustscan",
                    "-a", target,
                    "--",
                    "-oX", xml_file,
                    "-sV",
                    "-sC",
                    "-T4"
                ],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                return self._parse_nmap_xml(xml_file)
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timed out for {target}")
            return None
        except Exception as e:
            logger.error(f"Scan failed for {target}: {e}")
            return None

    def _parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output into structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            scan_results = []
            ipportmap = {}

            for host in root.findall("host"):
                host_data = self._parse_host(host)
                scan_results.append(host_data)
                
                # Build IP-Port map
                ip = host_data["address"]
                ipportmap[ip] = [
                    port["port"] 
                    for port in host_data["ports"] 
                    if port["state"] == "open"
                ]

            return {
                "results": scan_results,
                "ipportmap": ipportmap
            }
        except Exception as e:
            logger.error(f"XML parsing failed for {xml_file}: {e}")
            return None

    def _parse_host(self, host):
        """Parse individual host element"""
        address = host.find("address").get("addr")
        
        # Extract hostname
        hostname_element = host.find("hostnames/hostname")
        hostname = hostname_element.get("name") if hostname_element is not None else "Unknown"
        
        return {
            "address": address,
            "hostname": hostname,  # hostname is already a string
            "ports": [self._parse_port(p) for p in host.findall("ports/port")]
        }


    def _parse_port(self, port):
        """Parse individual port element"""
        service = port.find("service")
        return {
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": port.find("state").get("state"),
            "service": service.get("name") if service is not None else "Unknown",
            "version": service.get("version") if service is not None else "Unknown",
            "scripts": [
                {
                    "id": script.get("id"),
                    "output": script.get("output")
                } 
                for script in port.findall("script")
            ]
        }