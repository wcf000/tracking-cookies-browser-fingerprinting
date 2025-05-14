#!/usr/bin/env python3
"""
Tracking & Fingerprinting Project
Main application to run cookie extraction, analysis, and reporting.
"""

import os
import sys
import argparse
import json
from pathlib import Path
import webbrowser
import datetime

# Add project directory to path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

from cookie_analyzer import CookieExtractor, CookieClassifier, CookieReporter
from scripts.visualize import visualize_cookies, visualize_fingerprinting

def extract_and_analyze_cookies(browsers, output_dir, report=True, visualize=True, custom_paths=None):
    """Extract, analyze, and report on cookies from browsers."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    all_cookies = {}
    custom_paths = custom_paths or {}
    
    # Extract cookies from each browser
    for browser in browsers:
        print(f"\nExtracting cookies from {browser}...")
        try:
            # Check if a custom path was provided for this browser
            custom_path = custom_paths.get(browser)
            if custom_path:
                print(f"Using custom path: {custom_path}")
                
            extractor = CookieExtractor(browser=browser, custom_path=custom_path)
            cookies = extractor.extract()
            
            if cookies:
                all_cookies[browser] = cookies
                
                # Save raw cookie data
                cookie_file = output_path / f"{browser}_cookies.json"
                extractor.save_to_json(cookie_file)
                print(f"Saved raw cookie data to {cookie_file}")
            else:
                print(f"No cookies extracted from {browser}")
                
        except Exception as e:
            print(f"Error extracting cookies from {browser}: {e}")
            print("Try using --custom-path to specify the cookie database location manually")
    
    if not all_cookies:
        print("\nNo cookies were extracted. You can try these troubleshooting steps:")
        print("1. Close the browser before extraction")
        print("2. Specify the cookie database path manually with --custom-path")
        print("3. Run with administrator privileges")
        print("4. Or use sample data with the --sample flag")
        return False
    
    # Analyze cookies for each browser
    for browser, cookies in all_cookies.items():
        print(f"\nAnalyzing cookies from {browser}...")
        
        # Classify cookies
        classifier = CookieClassifier()
        classified_cookies = classifier.classify_cookies(cookies)
        
        print(f"Total cookies: {classified_cookies['summary']['total_cookies']}")
        print(f"Tracking cookies: {classified_cookies['summary']['tracking_cookies']} ({classified_cookies['summary']['tracking_percentage']}%)")
        
        # Generate and open report
        if report:
            reporter = CookieReporter(classified_cookies)
            report_content = reporter.generate_report()
            report_file = output_path / f"{browser}_cookie_report.html"
            reporter.save_report(report_content, report_file)
            print(f"Saved analysis report to {report_file}")
            webbrowser.open(f"file://{report_file.absolute()}")
        # Create visualizations if requested
        if visualize:
            viz_path = output_path / "visualizations" / browser
            visualize_cookies(cookies, viz_path)
    return True

def analyze_fingerprinting(data_file, output_dir, visualize=True):
    """Analyze fingerprinting data from file."""
    if not os.path.exists(data_file):
        print(f"Fingerprinting data file not found: {data_file}")
        return False
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    try:
        # Load fingerprinting data
        with open(data_file, 'r', encoding='utf-8') as f:
            fp_data = json.load(f)
            
        if not fp_data:
            print("No fingerprinting data found in file.")
            return False
            
        print(f"\nAnalyzing fingerprinting data from {data_file}...")
        print(f"Found {len(fp_data)} fingerprinting attempts.")
        
        # Basic analysis
        techniques = {}
        domains = {}
        
        for attempt in fp_data:
            # Count techniques
            technique = attempt.get('technique', 'Unknown')
            techniques[technique] = techniques.get(technique, 0) + 1
            
            # Count domains
            domain = attempt.get('domain', 'Unknown')
            domains[domain] = domains.get(domain, 0) + 1
        
        # Print summary
        print("\nTop fingerprinting techniques:")
        for technique, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {technique}: {count}")
            
        print("\nTop domains using fingerprinting:")
        for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {domain}: {count}")
        
        # Create visualizations if requested
        if visualize:
            viz_path = output_path / "visualizations" / "fingerprinting"
            visualize_fingerprinting(fp_data, viz_path)
        return True
    except Exception as e:
        print(f"Error analyzing fingerprinting data: {e}")
        return False

def load_sample_data(output_dir, data_type):
    """Load sample data for testing when real data extraction fails, jyust for debugging purposes"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    samples_dir = project_dir / "sample_data"
    if data_type == "cookies" or data_type == "both":
        # Create sample cookie data if it doesn't exist
        sample_cookies = [
            {
                "domain": "example.com",
                "name": "_ga",
                "value": "GA1.2.1234567890.1622547600",
                "path": "/",
                "expires": int((datetime.datetime.now() + datetime.timedelta(days=365)).timestamp()),
                "secure": True,
                "httpOnly": False,
                "created": int(datetime.datetime.now().timestamp()) - 86400,
                "lastAccessed": int(datetime.datetime.now().timestamp()),
                "session": False,
                "persistent": True
            },
            {
                "domain": "advertising.com",
                "name": "_fbp",
                "value": "fb.1.1622547600000.1234567890",
                "path": "/",
                "expires": int((datetime.datetime.now() + datetime.timedelta(days=90)).timestamp()),
                "secure": True,
                "httpOnly": False,
                "created": int(datetime.datetime.now().timestamp()) - 86400,
                "lastAccessed": int(datetime.datetime.now().timestamp()),
                "session": False,
                "persistent": True
            },
        ]    
        # Generate more sample cookies
        domains = ["example.com", "advertising.com", "tracker.net", "analytics.io", "ads.example.com"]
        cookie_names = ["_ga", "_gid", "visitor_id", "session", "_fbp", "uid", "id", "sid", "tracking", "preferences"]
        for i in range(30):
            domain = domains[i % len(domains)]
            name = cookie_names[i % len(cookie_names)]
            if i > len(cookie_names):
                name += str(i)    
            expires = int((datetime.datetime.now() + datetime.timedelta(days=(i % 365) + 1)).timestamp())  
            cookie = {
                "domain": domain,
                "name": name,
                "value": f"value{i}",
                "path": "/",
                "expires": expires,
                "secure": i % 2 == 0,
                "httpOnly": i % 3 == 0,
                "created": int(datetime.datetime.now().timestamp()) - 86400,
                "lastAccessed": int(datetime.datetime.now().timestamp()),
                "session": i % 5 == 0,
                "persistent": i % 5 != 0
            }
            sample_cookies.append(cookie)
        
        # Save sample cookies
        cookie_file = output_path / "sample_cookies.json"
        with open(cookie_file, "w", encoding="utf-8") as f:
            json.dump(sample_cookies, f, indent=2)
            
        print(f"Generated sample cookie data: {cookie_file}")
        
        # Analyze sample cookies
        classifier = CookieClassifier()
        classified_cookies = classifier.classify_cookies(sample_cookies)
        reporter = CookieReporter(classified_cookies)
        report_content = reporter.generate_report()
        report_file = output_path / "sample_cookie_report.html"
        reporter.save_report(report_content, report_file)
        print(f"Generated sample cookie report: {report_file}")
        webbrowser.open(f"file://{report_file.absolute()}")
        
        # Create visualizations
        viz_path = output_path / "visualizations" / "sample"
        visualize_cookies(sample_cookies, viz_path)
    
    if data_type == "fingerprinting" or data_type == "both":
        # Check if sample fingerprinting data exists, if not create it
        sample_fp_file = samples_dir / "fingerprinting_data.json"
        
        if not sample_fp_file.exists():
            print(f"No sample fingerprinting data found at {sample_fp_file}")
            print("Please create the sample_data directory and add fingerprinting_data.json")
            return False
        
        # Copy sample fingerprinting data to output directory
        fp_output_file = output_path / "sample_fingerprinting.json"
        with open(sample_fp_file, "r", encoding="utf-8") as src, open(fp_output_file, "w", encoding="utf-8") as dst:
            fp_data = json.load(src)
            json.dump(fp_data, dst, indent=2)
        print(f"Copied sample fingerprinting data: {fp_output_file}")

        analyze_fingerprinting(fp_output_file, output_dir)
    
    return True

def main():
    """Main function to run the tool."""
    parser = argparse.ArgumentParser(description="Tracking & Fingerprinting Analysis Tool")
    parser.add_argument("-b", "--browsers", nargs="+", default=["chrome", "firefox", "edge"],
                        help="Browsers to extract cookies from (default: chrome firefox edge)")
    parser.add_argument("-o", "--output", default="output",
                        help="Output directory for reports and data (default: 'output')")
    parser.add_argument("-f", "--fingerprinting", 
                        help="Path to fingerprinting data JSON file")
    parser.add_argument("-n", "--no-report", action="store_true",
                        help="Skip generating HTML reports")
    parser.add_argument("-v", "--no-visualize", action="store_true",
                        help="Skip generating visualizations")
    parser.add_argument("-c", "--cookies-only", action="store_true",
                        help="Only analyze cookies (skip fingerprinting)")
    parser.add_argument("-p", "--fp-only", action="store_true",
                        help="Only analyze fingerprinting (skip cookies)")
    parser.add_argument("-s", "--sample", choices=["cookies", "fingerprinting", "both"], 
                        help="Use sample data instead of extracting real data")
    parser.add_argument("--custom-path", nargs="+", 
                        help="Custom paths to cookie databases in format 'browser:path'")
    
    args = parser.parse_args()
    
    # Convert custom paths to dictionary
    custom_paths = {}
    if args.custom_path:
        for entry in args.custom_path:
            if ":" in entry:
                browser, path = entry.split(":", 1)
                custom_paths[browser.lower()] = path
            else:
                print(f"Warning: Invalid custom path format: {entry}. Use 'browser:path'")
    
    # Print banner
    print("\n" + "="*80)
    print(f"Tracking & Fingerprinting Analysis Tool")
    print(f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")
    
    output_dir = Path(args.output) / datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Use sample data if requested
    if args.sample:
        print(f"\nUSING SAMPLE DATA: {args.sample}")
        print("-" * 40)
        load_sample_data(output_dir, args.sample)
    else:
        # Analyze cookie
        if not args.fp_only:
            print("\nCOOKIE ANALYSIS")
            print("-" * 40)
            extract_and_analyze_cookies(
                args.browsers, 
                output_dir, 
                report=not args.no_report, 
                visualize=not args.no_visualize,
                custom_paths=custom_paths
            )
        # Analyze fingerprinting if a file is provided and not cookies-only
        if args.fingerprinting and not args.cookies_only:
            print("\nFINGERPRINTING ANALYSIS")
            print("-" * 40)
            analyze_fingerprinting(
                args.fingerprinting, 
                output_dir,
                visualize=not args.no_visualize
            )
    
    print("\n" + "="*80)
    print(f"Analysis completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Results saved to: {output_dir}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()