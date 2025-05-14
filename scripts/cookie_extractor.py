#!/usr/bin/env python3
"""
Cookie Extractor Script
This script extracts and analyzes cookies from browser databases.
"""

import os
import sqlite3
import json
import csv
import sys
import platform
import argparse
import datetime
import re
from pathlib import Path
from urllib.parse import urlparse

# Known tracking domains and prefixes
TRACKING_DOMAINS = [
    'analytics', 'tracker', 'pixel', 'ad.', 'ads.', 'adservice', 'doubleclick',
    'google-analytics', 'googletagmanager', 'googlesyndication', 'facebook',
    'twitter', 'linkedin', 'yahoo', 'criteo', 'quantserve', 'mediamath',
    'adroll', 'taboola', 'outbrain', 'pubmatic', 'rubiconproject', 'facebook',
    'adnxs', 'amazon-adsystem', 'scorecardresearch', 'casalemedia'
]

# Known tracking cookie prefixes
TRACKING_COOKIE_PREFIXES = [
    '_ga', '_gid', '_gcl', '_fbp', '_uetsid', '_uetvid', '_hjid', '_hj',
    'AMP_TOKEN', 'AMCV_', 'AMCVS_', 'NID', 'IDE', 'uuid', 'UIDR', 'VISITOR',
    'segment_', 'track', 'mp_', 'mixpanel', 'amplitude', 'parsely_',
    'personalization_id', 'utag_', 'intercom-', 'km_', 'id'
]


class CookieExtractor:
    """Class to extract and analyze cookies from various browsers."""

    def __init__(self, browser="chrome", output_dir="."):
        """Initialize the cookie extractor.
        
        Args:
            browser (str): Browser name (chrome, firefox, edge, safari)
            output_dir (str): Directory to save output files
        """
        self.browser = browser.lower()
        self.output_dir = Path(output_dir)
        self.cookies = []
        self.stats = {
            "total_cookies": 0,
            "tracking_cookies": 0,
            "domains": set(),
            "tracking_domains": set(),
            "oldest_cookie": None,
            "newest_cookie": None,
            "largest_cookie": {"name": "", "size": 0}
        }
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def get_cookie_db_path(self):
        """Get the path to the browser's cookie database."""
        system = platform.system()
        home = Path.home()
        
        if self.browser == "chrome":
            if system == "Windows":
                return home / "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
            elif system == "Darwin":  # macOS
                return home / "Library/Application Support/Google/Chrome/Default/Cookies"
            else:  # Linux
                return home / ".config/google-chrome/Default/Cookies"
        
        elif self.browser == "firefox":
            if system == "Windows":
                profiles_path = home / "AppData/Roaming/Mozilla/Firefox/Profiles"
            elif system == "Darwin":
                profiles_path = home / "Library/Application Support/Firefox/Profiles"
            else:
                profiles_path = home / ".mozilla/firefox"
            
            # Find the default profile
            profiles = list(profiles_path.glob("*.default*"))
            if not profiles:
                raise FileNotFoundError(f"No Firefox profile found in {profiles_path}")
            
            return profiles[0] / "cookies.sqlite"
        
        elif self.browser == "edge":
            if system == "Windows":
                return home / "AppData/Local/Microsoft/Edge/User Data/Default/Network/Cookies"
            elif system == "Darwin":
                return home / "Library/Application Support/Microsoft Edge/Default/Cookies"
            else:
                return home / ".config/microsoft-edge/Default/Cookies"
        
        else:
            raise ValueError(f"Unsupported browser: {self.browser}")
    
    def extract_cookies(self):
        """Extract cookies from the browser's database."""
        db_path = self.get_cookie_db_path()
        
        # Make a temp copy of the database if the browser is running
        temp_db = self.output_dir / f"temp_{self.browser}_cookies.db"
        try:
            import shutil
            shutil.copy2(db_path, temp_db)
            db_path = temp_db
        except Exception as e:
            print(f"Warning: Could not create temp copy of cookie database: {e}")
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            if self.browser in ["chrome", "edge"]:
                # Chrome/Edge schema
                query = """
                SELECT host_key, name, value, path, expires_utc, is_secure,
                       is_httponly, creation_utc, last_access_utc, 
                       has_expires, is_persistent
                FROM cookies
                """
            elif self.browser == "firefox":
                # Firefox schema
                query = """
                SELECT host, name, value, path, expiry, isSecure,
                       isHttpOnly, creationTime, lastAccessed, 
                       CASE WHEN expiry > 0 THEN 1 ELSE 0 END,
                       CASE WHEN expiry > 0 THEN 1 ELSE 0 END
                FROM moz_cookies
                """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                cookie = {
                    "domain": row[0],
                    "name": row[1],
                    "value": row[2],
                    "path": row[3],
                    "expires": self._format_expires(row[4]),
                    "secure": bool(row[5]),
                    "httpOnly": bool(row[6]),
                    "created": self._format_datetime(row[7]),
                    "lastAccessed": self._format_datetime(row[8]),
                    "persistent": bool(row[10]),
                    "size": len(row[2]) if row[2] else 0,
                    "isTracking": False
                }
                
                # Determine if this is a tracking cookie
                cookie["isTracking"] = self._is_tracking_cookie(cookie)
                
                self.cookies.append(cookie)
                
                # Update stats
                self.stats["total_cookies"] += 1
                self.stats["domains"].add(cookie["domain"])
                
                if cookie["isTracking"]:
                    self.stats["tracking_cookies"] += 1
                    self.stats["tracking_domains"].add(cookie["domain"])
                # Track oldest/newest cookies
                expires = cookie["expires"]
                if expires != "Session" and expires:
                    expires_date = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    if not self.stats["oldest_cookie"] or expires_date < datetime.datetime.fromisoformat(self.stats["oldest_cookie"]["expires"].replace("Z", "+00:00")):
                        self.stats["oldest_cookie"] = cookie
                    if not self.stats["newest_cookie"] or expires_date > datetime.datetime.fromisoformat(self.stats["newest_cookie"]["expires"].replace("Z", "+00:00")):
                        self.stats["newest_cookie"] = cookie
                
                # Track largest cookie
                if cookie["size"] > self.stats["largest_cookie"]["size"]:
                    self.stats["largest_cookie"] = {
                        "name": cookie["name"],
                        "domain": cookie["domain"],
                        "size": cookie["size"]
                    }
            conn.close()
            
            # Convert sets to lists for JSON serialization
            self.stats["domains"] = list(self.stats["domains"])
            self.stats["tracking_domains"] = list(self.stats["tracking_domains"])
            
            # Sort cookies by domain for easier reading
            self.cookies.sort(key=lambda c: c["domain"])
            
            print(f"Extracted {self.stats['total_cookies']} cookies from {self.browser} ({self.stats['tracking_cookies']} tracking cookies)")
            
            # Clean up temp file if it exists
            if temp_db.exists():
                temp_db.unlink()
            return True
        except Exception as e:
            print(f"Error extracting cookies from {self.browser}: {e}")
            if temp_db.exists():
                temp_db.unlink()
            return False
    
    def _format_expires(self, expires):
        """Format expires timestamp to ISO date string."""
        if not expires:
            return "Session"
        
        if self.browser in ["chrome", "edge"]:
            if expires == 0:
                return "Session"
            # Convert to seconds since epoch
            epoch_start = datetime.datetime(1601, 1, 1)
            delta = datetime.timedelta(microseconds=expires)
            date = epoch_start + delta
            return date.isoformat() + "Z"
        elif self.browser == "firefox":
            if expires == 0:
                return "Session"
            date = datetime.datetime.fromtimestamp(expires)
            return date.isoformat() + "Z"
    
    def _format_datetime(self, timestamp):
        """Format creation/access timestamp to ISO date string."""
        if not timestamp:
            return None
        if self.browser in ["chrome", "edge"]:
            epoch_start = datetime.datetime(1601, 1, 1)
            delta = datetime.timedelta(microseconds=timestamp)
            date = epoch_start + delta
            return date.isoformat() + "Z"
        elif self.browser == "firefox":
            date = datetime.datetime.fromtimestamp(timestamp / 1000000)
            return date.isoformat() + "Z"
    
    def _is_tracking_cookie(self, cookie):
        """Determine if a cookie is likely a tracking cookie."""
        # Check cookie name against known tracking prefixes
        if any(cookie["name"].lower().startswith(prefix.lower()) for prefix in TRACKING_COOKIE_PREFIXES):
            return True
        
        # Check domain against known tracking domains
        if any(tracker in cookie["domain"].lower() for tracker in TRACKING_DOMAINS):
            return True
        
        # Check if cookie is third-party (domain doesn't match host)
        domain = cookie["domain"]
        if domain.startswith('.'):
            domain = domain[1:]
        
        # Check for long expiration (> 1 year)
        if cookie["expires"] != "Session":
            try:
                expires = datetime.datetime.fromisoformat(cookie["expires"].replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if (expires - now).days > 365:
                    return True
            except:
                pass
        
        # Check for suspicious cookie values (long random strings)
        value = cookie["value"]
        if len(value) > 30 and re.match(r'^[A-Za-z0-9%+/=-]+$', value):
            return True
        
        return False
    
    def save_to_json(self):
        """Save extracted cookies to a JSON file."""
        if not self.cookies:
            print("No cookies to save. Run extract_cookies() first.")
            return False  
        output_file = self.output_dir / f"{self.browser}_cookies.json"
        data = {
            "metadata": {
                "browser": self.browser,
                "extracted_at": datetime.datetime.now().isoformat(),
                "stats": self.stats
            },
            "cookies": self.cookies
        }
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"Cookies saved to {output_file}")
            return True
        except Exception as e:
            print(f"Error saving cookies to JSON: {e}")
            return False
    
    def save_to_csv(self):
        """Save extracted cookies to a CSV file."""
        if not self.cookies:
            print("No cookies to save. Run extract_cookies() first.")
            return False
        output_file = self.output_dir / f"{self.browser}_cookies.csv"
        try:
            with open(output_file, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)  
                # Write header
                writer.writerow([
                    "Domain", "Name", "Path", "Value", "Expires", 
                    "Created", "Last Accessed", "Secure", "HttpOnly",
                    "Persistent", "Size (bytes)", "Is Tracking"
                ])
                
                # Write cookies
                for cookie in self.cookies:
                    writer.writerow([
                        cookie["domain"],
                        cookie["name"],
                        cookie["path"],
                        cookie["value"],
                        cookie["expires"],
                        cookie["created"],
                        cookie["lastAccessed"],
                        "Yes" if cookie["secure"] else "No",
                        "Yes" if cookie["httpOnly"] else "No",
                        "Yes" if cookie["persistent"] else "No",
                        cookie["size"],
                        "Yes" if cookie["isTracking"] else "No"
                    ])
            print(f"Cookies saved to {output_file}")
            return True
        except Exception as e:
            print(f"Error saving cookies to CSV: {e}")
            return False
    
    def generate_report(self):
        """Generate a detailed report of the cookie analysis."""
        if not self.cookies:
            print("No cookies to analyze. Run extract_cookies() first.")
            return False
        output_file = self.output_dir / f"{self.browser}_cookie_report.txt"
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Cookie Analysis Report - {self.browser.capitalize()}\n")
                f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
                f.write("=" * 80 + "\n\n")
                
                # Summary statistics
                f.write("Summary Statistics\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total cookies: {self.stats['total_cookies']}\n")
                f.write(f"Tracking cookies: {self.stats['tracking_cookies']} ({self.stats['tracking_cookies'] / self.stats['total_cookies'] * 100:.1f}%)\n")
                f.write(f"Unique domains: {len(self.stats['domains'])}\n")
                f.write(f"Tracking domains: {len(self.stats['tracking_domains'])}\n")
                
                # Largest cookie
                if self.stats['largest_cookie']['name']:
                    f.write(f"\nLargest cookie: {self.stats['largest_cookie']['name']} from {self.stats['largest_cookie']['domain']} ({self.stats['largest_cookie']['size']} bytes)\n")
                
                # Oldest/newest cookies
                if self.stats['oldest_cookie']:
                    f.write(f"\nOldest cookie: {self.stats['oldest_cookie']['name']} from {self.stats['oldest_cookie']['domain']} (expires {self.stats['oldest_cookie']['expires']})\n")
                if self.stats['newest_cookie']:
                    f.write(f"\nNewest cookie: {self.stats['newest_cookie']['name']} from {self.stats['newest_cookie']['domain']} (expires {self.stats['newest_cookie']['expires']})\n")
                
                # Top tracking domains
                f.write("\nTop Tracking Domains\n")
                f.write("-" * 80 + "\n")
                
                domain_counts = {}
                for cookie in self.cookies:
                    if cookie["isTracking"]:
                        domain = cookie["domain"]
                        domain_counts[domain] = domain_counts.get(domain, 0) + 1
                
                # Sort domains by cookie count
                sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
                
                # Display top 10 domains
                for i, (domain, count) in enumerate(sorted_domains[:10]):
                    f.write(f"{i+1}. {domain}: {count} tracking cookies\n")
                
                # List of all tracking cookies
                f.write("\nTracking Cookies\n")
                f.write("-" * 80 + "\n")
                f.write("Domain".ljust(40) + "Name".ljust(30) + "Expires".ljust(25) + "Size".ljust(10) + "\n")
                f.write("-" * 105 + "\n")
                
                for cookie in self.cookies:
                    if cookie["isTracking"]:
                        domain = cookie["domain"][:37] + "..." if len(cookie["domain"]) > 40 else cookie["domain"].ljust(40)
                        name = cookie["name"][:27] + "..." if len(cookie["name"]) > 30 else cookie["name"].ljust(30)
                        expires = cookie["expires"][:22] + "..." if len(cookie["expires"]) > 25 else cookie["expires"].ljust(25)
                        size = str(cookie["size"]).ljust(10)
                        f.write(f"{domain}{name}{expires}{size}\n")
                print(f"Report saved to {output_file}")
                return True      
        except Exception as e:
            print(f"Error generating report: {e}")
            return False


def main():
    """Main function to execute the cookie extraction process."""
    parser = argparse.ArgumentParser(description="Extract and analyze cookies from browser databases")
    parser.add_argument("-b", "--browser", choices=["chrome", "firefox", "edge"], default="chrome",
                        help="Browser to extract cookies from (default: chrome)")
    parser.add_argument("-o", "--output", default="output",
                        help="Output directory for extracted data (default: 'output')")
    parser.add_argument("-j", "--json", action="store_true", 
                        help="Save cookies to JSON file")
    parser.add_argument("-c", "--csv", action="store_true",
                        help="Save cookies to CSV file")
    parser.add_argument("-r", "--report", action="store_true",
                        help="Generate a detailed report")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Extract, save to JSON, CSV, and generate report")
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create extractor
    extractor = CookieExtractor(browser=args.browser, output_dir=output_dir)
    
    # Extract cookies
    if extractor.extract_cookies():
        # Save and generate reports based on arguments
        if args.json or args.all:
            extractor.save_to_json()
        if args.csv or args.all:
            extractor.save_to_csv()
        if args.report or args.all:
            extractor.generate_report()    
        if not (args.json or args.csv or args.report or args.all):   # Save to JSON by default
            extractor.save_to_json()
        print("Cookie extraction completed successfully.")
    else:
        print("Cookie extraction failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()