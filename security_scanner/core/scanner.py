from threading import Thread, Semaphore
from datetime import datetime
from security_scanner.modules import (
    DNSAnalyzer,
    APIClient,
    VulnerabilityScanner,
    WebCrawler,
    DarkwebChecker,
    EmailSecurityChecker,
    TlsSecurityChecker,
    PeopleFinder,
    TechnologyScanner,
    InfrastructureScanner,
)
from security_scanner.core.report_manager import ReportManager
from security_scanner.utils.config_loader import ConfigLoader
from security_scanner.utils.logger import logger

class SecurityAutomation:
    def __init__(self, domain, verbose=True, company_name=None):
        self.domain = domain
        self.verbose = verbose
        self.company_name = company_name or domain
        self.config = ConfigLoader.load()
        self.report = ReportManager.init_report(domain, company_name)
        self.api_client = APIClient(self.config)
        self.dns_analyzer = DNSAnalyzer(self.api_client, self.config)
        self.vuln_scanner = VulnerabilityScanner(self.config)
        self.web_crawler = WebCrawler(self.config)
        self.darkweb_checker = DarkwebChecker(self.api_client)
        self.people_finder = PeopleFinder(self.api_client, self.config)
        self.email_security_checker = EmailSecurityChecker(self.api_client, self.config)
        self.tls_security_checker = TlsSecurityChecker(self.api_client, self.config)
        self.tech_scanner = TechnologyScanner(self.config)
        self.infra_scanner = InfrastructureScanner(self.config)
        self.report["subdomains"].append(self.domain)

    def execute_scan(self):
        scan_tasks = [
            self._run_vulnerability_scan,
            self._run_web_crawling, # Google Dorking isn't working well, keeps getting blocked by google.
            self._run_darkweb_check,
            self._run_people_search,
            self._run_tech_scan,
            self._run_infra_scan,
            self._run_email_security_check,
            self._run_tls_security_check
        ]
        self._run_dns_analysis()

        threads = []
        for task in scan_tasks:
            t = Thread(target=task)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        ReportManager.save_report(self.report)
        logger.debug("Scan completed successfully")

    def _run_infra_scan(self):
        self.infra_scanner.scan(self.domain, self.report)

    def _run_dns_analysis(self):
        # self.dns_analyzer._query_crtsh(self.domain)
        self.dns_analyzer.get_dns_info(self.domain, self.report)
        # self.dns_analyzer._query_virustotal(self.domain)

    def _run_email_security_check(self):
        self.email_security_checker.check(self.domain, self.report)

    def _run_tls_security_check(self):
        self.tls_security_checker.check(self.domain, self.report)

    def _run_tech_scan(self):
        self.tech_scanner.scan(self.domain, self.report)

    def _run_vulnerability_scan(self):
        self.vuln_scanner.scan(self.domain, self.report)

    def _run_web_crawling(self):
        self.web_crawler.google_dorking(self.domain, self.report)
        self.web_crawler.capture_screenshots(self.domain, self.report)

    def _run_darkweb_check(self):
        self.darkweb_checker.check(self.domain, self.report)

    def _run_people_search(self):
        self.people_finder.find(self.domain, self.report)