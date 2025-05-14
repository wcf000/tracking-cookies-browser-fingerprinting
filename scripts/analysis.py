#!/usr/bin/env python3
"""
Cookie Analysis Script
This script extracts, classifies, and reports on cookies from browsers.
"""

import os
import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cookie_analyzer import CookieExtractor, CookieClassifier, CookieReporter

def main():
    """Main function to run the analysis."""
    parser = argparse.ArgumentParser(description="Extract and analyze browser cookies")
    parser.add_argument("-b", "--browsers", nargs="+", default=["chrome", "firefox", "edge"],
                        help="Browsers to extract cookies from (default: chrome firefox edge)")
    parser.add_argument("-o", "--output", default="output",
                        help="Output directory for reports and data (default: 'output')")
    parser.add_argument("-f", "--format", choices=["json", "csv", "both"], default="json",
                        help="Output format for raw cookie data (default: json)")
    parser.add_argument("-r", "--report", action="store_true",
                        help="Generate HTML report of analysis")
    parser.add_argument("-d", "--domains", nargs="+", 
                        help="Specific domains to focus analysis on")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Starting cookie extraction and analysis from {', '.join(args.browsers)}...")
    
    # Extract cookies
    results = {}
    all_cookies = {}
    
    for browser in args.browsers:
        extractor = CookieExtractor(browser=browser)
        cookies = extractor.extract()
        results[browser] = len(cookies)
        all_cookies[browser] = cookies
        
        # Save raw cookie data
        if args.format in ["json", "both"]:
            json_file = output_dir / f"{browser}_cookies.json"
            extractor.save_to_json(str(json_file))
            
        if args.format in ["csv", "both"]:
            csv_file = output_dir / f"{browser}_cookies.csv"
            save_to_csv(cookies, str(csv_file))
    
    print("Extraction results:")
    for browser, count in results.items():
        print(f"  {browser}: {count} cookies")
    
    # Classify and analyze cookies
    for browser, cookies in all_cookies.items():
        if not cookies:
            continue
            
        # Filter by domain if specified
        if args.domains:
            filtered_cookies = []
            for cookie in cookies:
                domain = cookie.get("domain", "")
                if any(d in domain for d in args.domains):
                    filtered_cookies.append(cookie)
            cookies = filtered_cookies
            print(f"Filtered to {len(cookies)} cookies for specified domains in {browser}")
        
        # Classify cookies
        classifier = CookieClassifier()
        classified_cookies = classifier.classify_cookies(cookies)
        
        print(f"\nAnalysis for {browser}:")
        print(f"  Total cookies: {classified_cookies['summary']['total_cookies']}")
        print(f"  Tracking cookies: {classified_cookies['summary']['tracking_cookies']} ({classified_cookies['summary']['tracking_percentage']}%)")
        
        # Generate report
        if args.report:
            reporter = CookieReporter(classified_cookies)
            report = reporter.generate_report()
            report_file = output_dir / f"{browser}_cookie_report.html"
            reporter.save_report(report, str(report_file))
            print(f"  Report saved to {report_file}")
            print(f"  To view the report, open the following file in your browser:")
            print(f"  {report_file.absolute()}")

def save_to_csv(cookies, output_file):
    """Save cookies to CSV format."""
    try:
        import csv
        
        # Determine all possible fields
        fields = set()
        for cookie in cookies:
            fields.update(cookie.keys())
        fields = sorted(list(fields))
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(cookies)
            
        print(f"Cookies saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving cookies to CSV: {e}")
        return False

if __name__ == "__main__":
    main()