from zapv2 import ZAPv2, alert
import time
import sys


def return_alerts_json(alerts):
    if not alerts:
        print(f'No alerts found')
        return {}

    results = {}
    for a in alerts:
        if a['risk'] == 'Informational':
            continue

        url = a['url']
        if url not in results:
            results[url] = []
        results[url].append({
            'alert': a['alert'],
            'risk': a['risk']
        })

    return results


class ZAPScanner:
    def __init__(self ,api_key='', base_url='http://localhost:8080'):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': base_url, 'https': base_url})

        self.zap.core.set_option_timeout_in_secs(600)
        self.zap.core.set_option_use_proxy_chain(False)
        self.zap.core.set_option_use_proxy_chain_auth(False)

    def spider_domain(self, domain):
        try:
            # Open domain initializing ZAP context
            self.zap.urlopen(domain)
        except Exception as e:
            raise Exception(f"Problem opening URL {domain}: {str(e)}")

        print(f'Target set to {domain}')

        # Start spider
        spider = self.zap.spider.scan(url=domain)
        sys.stdout.write(f'Spidering {domain}')

        while int(self.zap.spider.status(spider)) < 100:
            sys.stdout.write(f'\rSpidering {domain} ==> progress: {self.zap.spider.status(spider)}%')
            sys.stdout.flush()

        sys.stdout.write(f'\rSpidering {domain} ==> done!\n')

        alerts = self.zap.core.alerts(baseurl=domain)

        return return_alerts_json(alerts)

    def active_scan_domain(self, domain):
        try:
            # Open domain initializing ZAP context
            self.zap.urlopen(domain)
        except Exception as e:
            raise Exception(f"Problem opening URL {domain}: {str(e)}")

        print(f'Target set to {domain}')

        # Start active scan
        active_scan = self.zap.ascan.scan(domain)
        sys.stdout.write(f'\nActively scanning {domain} for vulnerabilities')

        while int(self.zap.ascan.status(active_scan)) < 100:
            sys.stdout.write(f'\rActively scanning {domain} for vulnerabilities ==> progress: {self.zap.ascan.status(active_scan)}%')
            sys.stdout.flush()

        sys.stdout.write(f'\rActively scanning {domain} for vulnerabilities ==> done!\n')

        # Fetch results
        alerts = self.zap.core.alerts(baseurl=domain)

        return return_alerts_json(alerts)
