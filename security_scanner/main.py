from security_scanner.core.scanner import SecurityAutomation
import argparse

def main():
    parser = argparse.ArgumentParser(description="Automated Security Scanner")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("-c", "--company", help="Company name", default=None)
    parser.add_argument("-v", "--verbose", help="Increase verbosity", action="store_true")
    args = parser.parse_args()

    scanner = SecurityAutomation(args.domain, args.verbose, args.company)
    scanner.execute_scan()
    print("Scan completed. Report saved to current directory.")

if __name__ == "__main__":
    main()