import xml.etree.ElementTree as ET
import subprocess

def add_unique_values(report, descriptor, values):
    existing = set(report.get(descriptor, []))
    report[descriptor] = list(existing.union(set(values)))

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        return [host.find("address").get("addr") for host in root.findall("host")]
    except Exception as e:
        logger.error(f"XML parse error: {e}")
        return []

def ensure_installed(command, install_cmd, prompt=None):
    """Check if a command is available and optionally install it"""
    if subprocess.run(["which", command], capture_output=True).returncode == 0:
        return True
        
    if prompt:
        choice = input(f"{prompt} [y/N]: ").strip().lower()
        if choice != 'y':
            return False
            
    return install_cmd()