from flask import Flask, request, jsonify
from zap import ZAPScanner

app = Flask(__name__)

# Initiate OWASP ZAP scanner
zap_scanner = ZAPScanner(api_key='40ed66c37b23b3bdf5de93f020cf66b1145814bfd7d4d0472c91423532c6515d', base_url='http://localhost:8080')

@app.route('/scan', methods=['POST'])
def scan_vulnerabilities():
    # Get data from JSON in the request
    data = request.get_json()
    domain = data.get('domain')
    scan = data.get('scan')

    if not domain:
        return jsonify({'error': 'No domain provided'}), 400

    if scan not in ['spider', 'active']:
        return jsonify({'error': 'Invalid scan type'}), 400

    elif scan == 'spider':
        try:
            if scan == 'spider':
                # Trigger spider scan using ZAP
                scan_results = zap_scanner.spider_domain(domain)
            elif scan == 'active':
                # Trigger active scan using ZAP
                scan_results = zap_scanner.active_scan_domain(domain)
            return jsonify(scan_results), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
