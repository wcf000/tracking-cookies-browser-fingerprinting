#!/usr/bin/env python3
"""
Visualization Script for Tracking Data
Creates visualizations from cookie and fingerprinting data
"""

import os
import sys
import json
import argparse
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from datetime import datetime

def load_data(file_path):
    """Load data from JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Add this function to categorize cookies
def categorize_cookie(cookie):
    """Categorize a cookie based on its name and domain."""
    name = cookie.get('name', '').lower()
    domain = cookie.get('domain', '').lower()
    
    # Analytics cookies
    if ('_ga' in name or 'analytics' in name or '_utm' in name or 
        'google-analytics' in domain or 'hotjar' in domain):
        return 'Analytics'
    
    # Advertising cookies
    if ('ads' in name or 'advert' in name or '_fbp' in name or 
        'doubleclick' in domain or 'ad.' in domain or 
        'adnxs' in domain or 'adsystem' in domain):
        return 'Advertising'
    
    # Session/functional cookies
    if ('session' in name or 'csrf' in name or 
        'auth' in name or 'login' in name):
        return 'Session/Authentication'
    
    # Social media cookies
    if ('facebook' in domain or 'twitter' in domain or 
        'linkedin' in domain or 'instagram' in domain or 
        'share' in name or 'social' in name):
        return 'Social Media'
    
    # Preferences cookies
    if ('pref' in name or 'setting' in name or 
        'consent' in name or 'notice' in name):
        return 'Preferences'
    
    # Performance/Technical cookies
    if ('cache' in name or '__cf' in name or 'load' in name or 
        'perf' in name or 'cloudflare' in domain):
        return 'Performance'
    
    # Known trackers
    known_trackers = [
        'doubleclick.net', 'google-analytics.com', 'facebook.net', 'facebook.com',
        'adnxs.com', 'amazon-adsystem.com', 'criteo.com', 'scorecardresearch.com',
        'googletagmanager.com', 'advertising.com', 'googlesyndication.com',
        'adsrvr.org', 'demdex.net', 'rlcdn.com', 'adition.com', 'hotjar.com',
        'quantserve.com', 'rubiconproject.com', 'mathtag.com', 'pubmatic.com',
        'casalemedia.com', 'moatads.com', 'addthis.com', 'taboola.com',
        'outbrain.com', 'sharethis.com', 'optimizely.com'
    ]
    
    if any(tracker in domain for tracker in known_trackers):
        return 'Tracking Network'
    
    # Default fallback
    return 'Other Tracker'

def visualize_cookies(cookies_data, output_dir):
    """Create visualizations for cookie data."""
    if not cookies_data:
        print("No cookie data to visualize")
        return
    # Convert to DataFrame for easier analysis
    df = pd.DataFrame(cookies_data)
    # Ensure output directory exists
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    df['category'] = df.apply(categorize_cookie, axis=1)
    
    # Generate category pie chart
    plt.figure(figsize=(10, 8))
    category_counts = df['category'].value_counts()
    category_counts.plot(kind='pie', autopct='%1.1f%%', colors=plt.cm.tab10.colors)
    plt.title('Cookie Categories')
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig(output_path / 'cookie_categories_pie.png')
    
    # 1. Domain distribution chart
    plt.figure(figsize=(12, 6))
    domain_counts = df['domain'].value_counts().head(15)  # Top 15 domains
    domain_counts.plot(kind='bar', color='cornflowerblue')
    plt.title('Top Domains by Cookie Count')
    plt.xlabel('Domain')
    plt.ylabel('Number of Cookies')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_path / 'cookie_domains.png')
    
    # 2. Session vs Persistent cookies
    plt.figure(figsize=(8, 8))
    session_counts = df['session'].value_counts()
    plt.pie(session_counts, labels=['Persistent', 'Session'] if len(session_counts) > 1 else ['Session'],
            autopct='%1.1f%%', colors=['#ff9999','#66b3ff'])
    plt.title('Session vs Persistent Cookies')
    plt.savefig(output_path / 'cookie_types.png')
    
    # 3. Expiration time analysis
    try:
        # Convert to datetime and handle NaN values
        df['expires_dt'] = pd.to_datetime(df['expires'], unit='s', errors='coerce')
        now = pd.Timestamp.now()
        df['days_until_expiry'] = (df['expires_dt'] - now).dt.days
        # Filter out expired cookies and session cookies
        valid_cookies = df[df['days_until_expiry'] > 0].copy()
        if not valid_cookies.empty:
            # Create expiration time bins
            bins = [0, 1, 7, 30, 90, 365, float('inf')]
            labels = ['1 day', '1 week', '1 month', '3 months', '1 year', '> 1 year']
            valid_cookies['expiry_category'] = pd.cut(valid_cookies['days_until_expiry'], bins=bins, labels=labels)
            # Plot expiration distribution
            plt.figure(figsize=(10, 6))
            expiry_counts = valid_cookies['expiry_category'].value_counts().sort_index()
            expiry_counts.plot(kind='bar', color='green')
            plt.title('Cookie Expiration Distribution')
            plt.xlabel('Time Until Expiration')
            plt.ylabel('Number of Cookies')
            plt.tight_layout()
            plt.savefig(output_path / 'cookie_expiration.png')
    except Exception as e:
        print("Could not analyze cookie expiration times")
    
    # 4. HTTP Only and Secure flags
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    httponly_counts = df['httpOnly'].value_counts() if 'httpOnly' in df.columns else pd.Series([0, 0], index=[False, True])
    plt.pie(httponly_counts, labels=['Not HTTP Only', 'HTTP Only'] if len(httponly_counts) > 1 else ['Not HTTP Only'],
            autopct='%1.1f%%', colors=['#ff9999','#66b3ff'])
    plt.title('HTTP Only Cookies')
    
    plt.subplot(1, 2, 2)
    secure_counts = df['secure'].value_counts() if 'secure' in df.columns else pd.Series([0, 0], index=[False, True])
    plt.pie(secure_counts, labels=['Not Secure', 'Secure'] if len(secure_counts) > 1 else ['Not Secure'],
            autopct='%1.1f%%', colors=['#ff9999','#66b3ff'])
    plt.title('Secure Cookies')
    
    plt.tight_layout()
    plt.savefig(output_path / 'cookie_security.png')
    
    print(f"Cookie visualizations saved to {output_path}")

def visualize_fingerprinting(fp_data, output_dir):
    """Create visualizations for fingerprinting data."""
    if not fp_data:
        print("No fingerprinting data to visualize")
        return
    
    # Ensure output directory exists
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Extract relevant data
    techniques = {}
    domains = {}
    timestamps = []
    
    for attempt in fp_data:
        # Count techniques
        technique = attempt.get('technique', 'Unknown')
        techniques[technique] = techniques.get(technique, 0) + 1
        
        # Count domains
        domain = attempt.get('domain', 'Unknown')
        domains[domain] = domains.get(domain, 0) + 1
        
        # Collect timestamps
        if 'timestamp' in attempt:
            try:
                timestamps.append(datetime.fromisoformat(attempt['timestamp'].replace('Z', '+00:00')))
            except (ValueError, TypeError):
                pass
    
    # 1. Techniques distribution
    plt.figure(figsize=(12, 6))
    technique_items = sorted(techniques.items(), key=lambda x: x[1], reverse=True)
    tech_names = [item[0] for item in technique_items[:10]]
    tech_counts = [item[1] for item in technique_items[:10]]
    
    plt.barh(tech_names, tech_counts, color='cornflowerblue')
    plt.xlabel('Number of Attempts')
    plt.title('Top Fingerprinting Techniques')
    plt.gca().invert_yaxis()  # To have highest count at top
    plt.tight_layout()
    plt.savefig(output_path / 'fingerprinting_techniques.png')
    
    # 2. Domain distribution
    plt.figure(figsize=(12, 6))
    domain_items = sorted(domains.items(), key=lambda x: x[1], reverse=True)
    domain_names = [item[0] for item in domain_items[:10]]
    domain_counts = [item[1] for item in domain_items[:10]]
    
    plt.barh(domain_names, domain_counts, color='cornflowerblue')
    plt.xlabel('Number of Attempts')
    plt.title('Top Domains Using Fingerprinting')
    plt.gca().invert_yaxis()  # To have highest count at top
    plt.tight_layout()
    plt.savefig(output_path / 'fingerprinting_domains.png')
    
    # 3. Time distribution (if timestamps are available)
    if timestamps:
        # Extract hour of day
        hours = [ts.hour for ts in timestamps]
        plt.figure(figsize=(12, 6))
        plt.hist(hours, bins=24, range=(0, 24), color='cornflowerblue', rwidth=0.8)
        plt.xlabel('Hour of Day (0-23)')
        plt.ylabel('Number of Attempts')
        plt.title('Fingerprinting Attempts by Hour of Day')
        plt.xticks(range(0, 24, 2))
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path / 'fingerprinting_time.png')
    print(f"Fingerprinting visualizations saved to {output_path}")

def main():
    """Main function to run the visualization."""
    parser = argparse.ArgumentParser(description="Visualize tracking data")
    parser.add_argument("-c", "--cookies", help="Path to cookies JSON file")
    parser.add_argument("-f", "--fingerprinting", help="Path to fingerprinting JSON file")
    parser.add_argument("-o", "--output", default="visualizations",
                        help="Output directory for visualizations (default: 'visualizations')")
    
    args = parser.parse_args()
    
    if not args.cookies and not args.fingerprinting:
        parser.error("At least one of --cookies or --fingerprinting must be provided")
    
    if args.cookies:
        try:
            cookies_data = load_data(args.cookies)
            visualize_cookies(cookies_data, args.output)
        except Exception as e:
            print(f"Error visualizing cookie data: {e}")
    
    if args.fingerprinting:
        try:
            fingerprinting_data = load_data(args.fingerprinting)
            visualize_fingerprinting(fingerprinting_data, args.output)
        except Exception as e:
            print(f"Error visualizing fingerprinting data: {e}")

if __name__ == "__main__":
    main()