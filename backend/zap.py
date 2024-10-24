from zapv2 import ZAPv2
import sys

class ZAPScanner:
    def __init__(self ,api_key='', base_url='http://localhost:8080'):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': base_url, 'https': base_url})

        self.zap.core.set_option_timeout_in_secs(600)

    def scan_domain(self, domain):
        try:
            # Open domain initializing ZAP context
            self.zap.urlopen(domain)
        except Exception as e:
            raise Exception(f"Problem opening URL {domain}: {str(e)}")

        print(f'Target set to {domain}')

        # Start spider
        spider = self.zap.spider.scan(domain)
        print(f'Spidering {domain}')

        while int(self.zap.spider.status(spider)) < 100:
            sys.stdout.write(f'\rProgress: {self.zap.spider.status(spider)}%')
            sys.stdout.flush()

        sys.stdout.write(f'\rDone!')

        # Start active scan
        active_scan = self.zap.ascan.scan(domain)
        print(f'\nActively scanning {domain} for vulnerabilities')

        while int(self.zap.ascan.status(active_scan)) < 100:
            sys.stdout.write(f'\rProgress: {self.zap.ascan.status(active_scan)}%')
            sys.stdout.flush()

        sys.stdout.write(f'\rDone!\n')

        # Fetch results
        alerts = self.zap.core.alerts(baseurl=domain)

        results = {}
        for alert in alerts:
            if alert['risk'] == 'Informational':
                continue

            url = alert['url']
            if url not in results:
                results[url] = []
            results[url].append({
                'alert': alert['alert'],
                'risk': alert['risk']
            })

        return results