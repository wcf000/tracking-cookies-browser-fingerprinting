"""
Cookie Reporter Module
Generates reports about cookie analysis results.
"""

import json
import os
import datetime
from collections import Counter, defaultdict

class CookieReporter:
    """Class to generate reports about cookie analysis results."""
    
    def __init__(self, classified_cookies):
        """
        Initialize the cookie reporter.
        
        Args:
            classified_cookies (dict): Dictionary with classified cookies from the classifier.
        """
        self.cookies = classified_cookies
    
    def generate_report(self):
        """Generate an HTML report of the analysis."""
        # Check for empty data or missing summary
        if not self.cookies or 'summary' not in self.cookies:
            tracking_cookies = self.cookies.get('tracking', [])
            non_tracking_cookies = self.cookies.get('non_tracking', [])
            
            total_cookies = len(tracking_cookies) + len(non_tracking_cookies)
            tracking_count = len(tracking_cookies)
            
            # Count third-party cookies
            third_party_count = 0
            for cookie in tracking_cookies + non_tracking_cookies:
                if cookie.get('classification', {}).get('is_third_party', False):
                    third_party_count += 1
                
            # Create summary if it doesn't exist or has zero values
            if 'summary' not in self.cookies or self.cookies['summary'].get('total_cookies', 0) == 0:
                self.cookies['summary'] = {
                    'total_cookies': total_cookies,
                    'tracking_cookies': tracking_count,
                    'non_tracking_cookies': len(non_tracking_cookies),
                    'tracking_percentage': round((tracking_count / total_cookies * 100) if total_cookies > 0 else 0, 1),
                    'third_party_cookies': third_party_count,
                    'first_party_cookies': total_cookies - third_party_count
                }
        
        tracking_cookies = self.cookies.get("tracking", [])
        non_tracking_cookies = self.cookies.get("non_tracking", [])
        summary = self.cookies.get("summary", {})
        
        # Generate insights about the data
        domain_stats = self._analyze_domains(tracking_cookies)
        expiration_stats = self._analyze_expirations(tracking_cookies)
        tracker_types = self._analyze_tracker_types(tracking_cookies)
        
        # Make sure third-party and first-party counts are in the summary
        if 'third_party_cookies' not in summary or summary['third_party_cookies'] <= 10:
            all_cookies = tracking_cookies + non_tracking_cookies
            print(f"Recounting third-party cookies with improved detection...")
            third_party_count = 0
            for cookie in all_cookies:
                domain = cookie.get('domain', '').lstrip('.')
                
                # Common tracking domains - detect these as third-party
                tracking_domains = [
                    'doubleclick', 'google-analytics', 'facebook', 'fbcdn', 
                    'amazon-adsystem', 'adnxs', 'adsrvr', 'rubiconproject',
                    'criteo', 'scorecardresearch', 'analytics', 'tracker', 'adserver',
                    'pixel', 'ad.', 'ads.', 'stat.', 'stats.', 'track.', 'tag',
                    'pubmatic', 'sharethrough', 'quantserve', 'outbrain', 'taboola',
                    'hotjar', 'linkedin', 'pinterest', 'snap', 'tiktok', 'mathtag'
                ]
                
                # Check if domain contains any tracking domain pattern
                is_third_party = False
                for tracking_domain in tracking_domains:
                    if tracking_domain in domain:
                        is_third_party = True
                        break
                if is_third_party or cookie.get('classification', {}).get('is_third_party', False):
                    third_party_count += 1
            summary['third_party_cookies'] = third_party_count
            summary['first_party_cookies'] = summary.get('total_cookies', 0) - third_party_count
        
        # Format the HTML report
        report = self._format_html_report(
            summary, 
            domain_stats, 
            expiration_stats, 
            tracker_types, 
            tracking_cookies, 
            non_tracking_cookies
        )
        
        return report
    
    def save_report(self, report, output_file):
        """
        Save the report to a file.
        
        Args:
            report (str): The report content.
            output_file (str): Path to save the report.
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
        except Exception as e:
            print(f"Error saving report: {e}")
    
    def _analyze_domains(self, tracking_cookies):
        """Analyze domains in tracking cookies."""
        domains = Counter()
        third_party_domains = Counter()
        
        for cookie in tracking_cookies:
            domain = cookie.get('domain', '')
            domains[domain] += 1
            
            if cookie.get('classification', {}).get('is_third_party', False):
                third_party_domains[domain] += 1
        
        return {
            'top_domains': domains.most_common(10),
            'third_party_domains': third_party_domains.most_common(10),
            'total_unique_domains': len(domains)
        }
    
    def _analyze_expirations(self, tracking_cookies):
        """Analyze expiration times in tracking cookies."""
        now = datetime.datetime.now()
        expirations = {
            'session': 0,
            'short_term': 0,  # < 1 day
            'medium_term': 0,  # 1-30 days
            'long_term': 0,    # 30-365 days
            'persistent': 0    # > 365 days
        }
        max_expiry = None
        max_expiry_cookie = None
        for cookie in tracking_cookies:
            expires = cookie.get('expires')
            if not expires or cookie.get('session', False):
                expirations['session'] += 1
                continue   
            try:
                if isinstance(expires, (int, float)):
                    expiry_date = datetime.datetime.fromtimestamp(expires)
                    days_until_expiry = (expiry_date - now).days
                    
                    if days_until_expiry <= 0:
                        continue
                    elif days_until_expiry < 1:
                        expirations['short_term'] += 1
                    elif days_until_expiry < 30:
                        expirations['medium_term'] += 1
                    elif days_until_expiry < 365:
                        expirations['long_term'] += 1
                    else:
                        expirations['persistent'] += 1
                        
                    # Track the cookie with the longest expiration
                    if max_expiry is None or days_until_expiry > max_expiry:
                        max_expiry = days_until_expiry
                        max_expiry_cookie = cookie

            except Exception as e:
                print(f"Error processing expiration date: {e}")
        
        return {
            'distribution': expirations,
            'max_expiry_days': max_expiry,
            'max_expiry_cookie': max_expiry_cookie
        }
    
    def _analyze_tracker_types(self, tracking_cookies):
        """Analyze types of trackers based on classification features."""
        tracker_types = {
            'known_trackers': 0,
            'fingerprinting': 0,
            'long_term': 0,
            'suspicious_name': 0 
        }
        
        for cookie in tracking_cookies:
            classification = cookie.get('classification', {})
            features = classification.get('features', {})
            
            if features.get('known_tracker', False):
                tracker_types['known_trackers'] += 1
            
            if features.get('fingerprinting_related', False):
                tracker_types['fingerprinting'] += 1
            
            if features.get('long_expiration', False):
                tracker_types['long_term'] += 1
                
            if features.get('suspicious_name', False):
                tracker_types['suspicious_name'] += 1
        
        return tracker_types
    
    def _format_html_report(self, summary, domain_stats, expiration_stats, tracker_types, 
                           tracking_cookies, non_tracking_cookies):
        """Format the analysis results as an HTML report."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cookie Tracking Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .summary-box {{ background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                .stats-container {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }}
                .stats-box {{ flex: 1; min-width: 300px; background-color: #f8f9fa; border-radius: 5px; padding: 15px; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .tracking {{ color: #e74c3c; }}
                .non-tracking {{ color: #27ae60; }}
                .chart-container {{ margin-bottom: 30px; }}
                .cookie-detail {{ background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 10px; }}
                .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; }}
                .badge-danger {{ background-color: #f8d7da; color: #721c24; }}
                .badge-warning {{ background-color: #fff3cd; color: #856404; }}
                .badge-info {{ background-color: #d1ecf1; color: #0c5460; }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <div class="container">
                <h1>Cookie Tracking Analysis Report</h1>
                <p>Generated on: {now}</p>
                
                <div class="summary-box">
                    <h2>Summary</h2>
                    <p>Total cookies analyzed: <strong>{summary.get('total_cookies', 0)}</strong></p>
                    <p>Tracking cookies: <strong class="tracking">{summary.get('tracking_cookies', 0)} ({summary.get('tracking_percentage', 0)}%)</strong></p>
                    <p>Non-tracking cookies: <strong class="non-tracking">{summary.get('non_tracking_cookies', 0)} ({100 - summary.get('tracking_percentage', 0):.1f}%)</strong></p>
                    <p>Third-party cookies: <strong>{summary.get('third_party_cookies', 0)} ({summary.get('third_party_cookies', 0)/max(summary.get('total_cookies', 1), 1)*100:.1f}%)</strong></p>
                    <p>First-party cookies: <strong>{summary.get('first_party_cookies', 0)} ({summary.get('first_party_cookies', 0)/max(summary.get('total_cookies', 1), 1)*100:.1f}%)</strong></p>
                </div>
                
                <div class="stats-container">
                    <div class="stats-box">
                        <h3>Top Tracking Domains</h3>
                        <table>
                            <tr>
                                <th>Domain</th>
                                <th>Count</th>
                            </tr>
        """
        
        # Add top domains to the table
        for domain, count in domain_stats['top_domains']:
            html += f"""
                            <tr>
                                <td>{domain}</td>
                                <td>{count}</td>
                            </tr>
            """
        
        html += f"""
                        </table>
                        <p>Total unique domains: {domain_stats['total_unique_domains']}</p>
                    </div>
                    
                    <div class="stats-box">
                        <h3>Cookie Expiration</h3>
                        <div class="chart-container">
                            <canvas id="expirationChart"></canvas>
                        </div>
                        <p>Longest expiring cookie: <strong>{expiration_stats['max_expiry_days']} days</strong></p>
                        <p>Cookie name: <strong>{expiration_stats.get('max_expiry_cookie', {}).get('name', 'N/A')}</strong></p>
                        <p>Domain: <strong>{expiration_stats.get('max_expiry_cookie', {}).get('domain', 'N/A')}</strong></p>
                    </div>
                </div>
                
                <div class="stats-container">
                    <div class="stats-box">
                        <h3>Tracker Types</h3>
                        <div class="chart-container">
                            <canvas id="trackerTypesChart"></canvas>
                        </div>
                    </div>
                    
                    <div class="stats-box">
                        <h3>Tracking Features</h3>
                        <div class="chart-container">
                            <canvas id="trackingFeaturesChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <h2>Top Tracking Cookies</h2>
        """
        
        # Add top tracking cookies
        for i, cookie in enumerate(tracking_cookies[:10]):
            classification = cookie.get('classification', {})
            features = classification.get('features', {})
            reasons = classification.get('reasons', [])
            
            feature_badges = ""
            if features.get('known_tracker', False):
                feature_badges += '<span class="badge badge-danger">Known Tracker</span>'
            if features.get('fingerprinting_related', False):
                feature_badges += '<span class="badge badge-danger">Fingerprinting</span>'
            if features.get('long_expiration', False):
                feature_badges += '<span class="badge badge-warning">Long Expiration</span>'
            if features.get('suspicious_name', False):
                feature_badges += '<span class="badge badge-info">Suspicious Name</span>'
            if classification.get('is_third_party', False):
                feature_badges += '<span class="badge badge-warning">Third Party</span>'
            
            html += f"""
                <div class="cookie-detail">
                    <h3>{i+1}. {cookie.get('name', 'N/A')}</h3>
                    <p><strong>Domain:</strong> {cookie.get('domain', 'N/A')}</p>
                    <p><strong>Expires:</strong> {datetime.datetime.fromtimestamp(cookie.get('expires', 0)).strftime('%Y-%m-%d %H:%M:%S') if cookie.get('expires') else 'Session'}</p>
                    <p><strong>Secure:</strong> {cookie.get('secure', False)}</p>
                    <p><strong>HttpOnly:</strong> {cookie.get('httpOnly', False)}</p>
                    <p><strong>Features:</strong> {feature_badges}</p>
                    <p><strong>Reasons:</strong></p>
                    <ul>
            """
            
            for reason in reasons:
                html += f"<li>{reason}</li>"
            
            html += """
                    </ul>
                </div>
            """
        
        # Add JavaScript for charts
        expiration_data = expiration_stats['distribution']
        tracking_features = summary.get('tracking_by_feature', {})
        
        html += f"""
                <script>
                    // Expiration chart
                    const expirationCtx = document.getElementById('expirationChart').getContext('2d');
                    const expirationChart = new Chart(expirationCtx, {{
                        type: 'pie',
                        data: {{
                            labels: ['Session', 'Short Term (<1 day)', 'Medium Term (1-30 days)', 'Long Term (30-365 days)', 'Persistent (>365 days)'],
                            datasets: [{{
                                data: [
                                    {expiration_data['session']}, 
                                    {expiration_data['short_term']}, 
                                    {expiration_data['medium_term']}, 
                                    {expiration_data['long_term']}, 
                                    {expiration_data['persistent']}
                                ],
                                backgroundColor: [
                                    '#4dc9f6',
                                    '#f67019',
                                    '#f53794',
                                    '#537bc4',
                                    '#acc236'
                                ]
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            plugins: {{
                                legend: {{
                                    position: 'top',
                                }}
                            }}
                        }}
                    }});
                    
                    // Tracker types chart
                    const trackerTypesCtx = document.getElementById('trackerTypesChart').getContext('2d');
                    const trackerTypesChart = new Chart(trackerTypesCtx, {{
                        type: 'bar',
                        data: {{
                            labels: ['Known Trackers', 'Fingerprinting', 'Long Term', 'Suspicious Name'],
                            datasets: [{{
                                label: 'Count',
                                data: [
                                    {tracker_types['known_trackers']},
                                    {tracker_types['fingerprinting']},
                                    {tracker_types['long_term']},
                                    {tracker_types['suspicious_name']}
                                ],
                                backgroundColor: '#75b798'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            scales: {{
                                y: {{
                                    beginAtZero: true
                                }}
                            }}
                        }}
                    }});
                    
                    // Tracking features chart
                    const trackingFeaturesCtx = document.getElementById('trackingFeaturesChart').getContext('2d');
                    const trackingFeaturesData = {{
                        'Known Tracker': {tracker_types.get('known_trackers', 0)},
                        'Long Expiration': {tracker_types.get('long_term', 0)},
                        'Suspicious Name': {tracker_types.get('suspicious_name', 0) if 'suspicious_name' in tracker_types else 0},
                        'Fingerprinting': {tracker_types.get('fingerprinting', 0)}
                    }};

                    const trackingFeaturesChart = new Chart(trackingFeaturesCtx, {{
                        type: 'bar',
                        data: {{
                            labels: Object.keys(trackingFeaturesData),
                            datasets: [{{
                                label: 'Count',
                                data: Object.values(trackingFeaturesData),
                                backgroundColor: '#dc3545'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            scales: {{
                                y: {{
                                    beginAtZero: true
                                }}
                            }}
                        }}
                    }});
                </script>
            </div>
        </body>
        </html>
        """
        return html