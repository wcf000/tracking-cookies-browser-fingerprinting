"""
Cookie Classifier Module
Classifies cookies as tracking or non-tracking based on various heuristics.
"""

from urllib.parse import urlparse
import re
from collections import Counter
import datetime

class CookieClassifier:
    """Classifies cookies as tracking or non-tracking."""
    
    def __init__(self):
        """Initialize the cookie classifier with tracking heuristics."""
        # Known tracking domains
        self.tracking_domains = [
            'analytics', 'tracker', 'pixel', 'ad.', 'ads.', 'adservice', 'doubleclick',
            'google-analytics', 'googletagmanager', 'googlesyndication', 'facebook',
            'twitter', 'linkedin', 'yahoo', 'criteo', 'quantserve', 'mediamath',
            'adroll', 'taboola', 'outbrain', 'pubmatic', 'rubiconproject', 'facebook',
            'adnxs', 'amazon-adsystem', 'scorecardresearch', 'casalemedia'
        ]
        
        # Known tracking cookie prefixes
        self.tracking_prefixes = [
            '_ga', '_gid', '_gcl', '_fbp', '_uetsid', '_uetvid', '_hjid', '_hj',
            'AMP_TOKEN', 'AMCV_', 'AMCVS_', 'NID', 'IDE', 'uuid', 'UIDR', 'VISITOR',
            'segment_', 'track', 'mp_', 'mixpanel', 'amplitude', 'parsely_',
            'personalization_id', 'utag_', 'intercom-', 'km_', 'id'
        ]
    
    def classify_cookies(self, cookies):
        """
        Classify cookies as tracking or non-tracking.
        """
        tracking_cookies = []
        non_tracking_cookies = []
        third_party_cookies = 0
        
        # Extract all domains with special cookie domain handling
        all_domains = set()
        extracted_domains = set()
        
        for cookie in cookies:
            if 'domain' in cookie:
                domain = cookie['domain'].lstrip('.')
                extracted_domains.add(domain)
        
        # Process extracted domains to handle common patterns
        for domain in extracted_domains:
            all_domains.add(domain)
            
            # Extract primary domain (for domains like sub.example.com)
            parts = domain.split('.')
            if len(parts) > 2:
                primary_domain = '.'.join(parts[-2:])
                all_domains.add(primary_domain)
        
        for cookie in cookies:
            classification = self._classify_cookie(cookie, all_domains)
            cookie['classification'] = classification
            
            # Count third-party cookies
            if classification['is_third_party']:
                third_party_cookies += 1            
            if classification['is_tracking']:
                tracking_cookies.append(cookie)
            else:
                non_tracking_cookies.append(cookie)
        
        # Generate summary statistics
        total_cookies = len(cookies)
        tracking_percentage = round((len(tracking_cookies) / total_cookies * 100) if total_cookies > 0 else 0, 1)
        
        summary = {
            'total_cookies': total_cookies,
            'tracking_cookies': len(tracking_cookies),
            'non_tracking_cookies': len(non_tracking_cookies),
            'tracking_percentage': tracking_percentage,
            'unique_domains': len(all_domains),
            'third_party_cookies': third_party_cookies,
            'first_party_cookies': total_cookies - third_party_cookies
        }
        
        return {
            'tracking': tracking_cookies,
            'non_tracking': non_tracking_cookies,
            'summary': summary
        }
    
    def _classify_cookie(self, cookie, all_domains):
        """
        Classify an individual cookie.
        
        Args:
            cookie (dict): The cookie to classify.
            all_domains (set): Set of all domains across all cookies.
            
        Returns:
            dict: Classification details.
        """
        is_tracking = False
        reasons = []
        
        # Get cookie attributes
        name = cookie.get('name', '')
        domain = cookie.get('domain', '').lstrip('.')
        expires = cookie.get('expires')
        path = cookie.get('path', '')
        
        # Feature flags
        features = {
            'known_tracker': False,
            'fingerprinting_related': False, 
            'long_expiration': False,
            'third_party': False,
            'suspicious_name': False
        }
        
        # Check for common tracking cookie prefixes
        for prefix in self.tracking_prefixes:
            if name.lower().startswith(prefix.lower()):
                is_tracking = True
                reasons.append(f"Name starts with tracking prefix '{prefix}'")
                features['known_tracker'] = True
                break
        
        # Check for ID-like values in cookie name
        if re.search(r'(id|uid|user|visitor|session|tracking)', name.lower()):
            is_tracking = True
            reasons.append("Name contains tracking identifiers")
            features['suspicious_name'] = True
        
        # Check domain against known tracking domains
        for tracking_domain in self.tracking_domains:
            if tracking_domain in domain:
                is_tracking = True
                reasons.append(f"Domain contains known tracking pattern '{tracking_domain}'")
                features['known_tracker'] = True
                break
        
        # Check if cookie is third-party
        is_third_party, third_party_reason = self._is_third_party_cookie(cookie, all_domains)
        features['third_party'] = is_third_party
        
        if is_third_party:
            is_tracking = True
            reasons.append(third_party_reason)
        
        # Check expiration time (long-lived cookies are more likely to be tracking)
        if isinstance(expires, (int, float)):
            try:
                expiry_date = datetime.datetime.fromtimestamp(expires)
                now = datetime.datetime.now()
                days_until_expiry = (expiry_date - now).days
                
                if days_until_expiry > 365:
                    is_tracking = True
                    reasons.append(f"Long-lived cookie (expires in {days_until_expiry} days)")
                    features['long_expiration'] = True
            except Exception:
                pass
        
        # Check for fingerprinting related cookies
        if any(fp_term in name.lower() for fp_term in ['canvas', 'webgl', 'audio', 'fingerprint', 'device']):
            is_tracking = True
            reasons.append("Cookie name suggests fingerprinting")
            features['fingerprinting_related'] = True
        
        return {
            'is_tracking': is_tracking,
            'reasons': reasons,
            'is_third_party': is_third_party,
            'features': features
        }

    def _is_third_party_cookie(self, cookie, all_domains):
        """
        Determine if a cookie is third-party with significantly improved detection.
        Uses multiple signals including known trackers, cookie properties, and domain analysis.
        
        Returns:
            tuple: (is_third_party, reason)
        """
        cookie_domain = cookie.get('domain', '').lstrip('.')
        cookie_name = cookie.get('name', '')
        
        # No domain
        if not cookie_domain:
            return False, ""
            
        # 1. EXPANDED KNOWN TRACKING DOMAINS LIST
        expanded_tracking_domains = [
            # Analytics & measurement
            'google-analytics', 'doubleclick', 'analytics', 'segment.io', 'mixpanel', 
            'amplitude', 'chartbeat', 'clarity.ms', 'hotjar', 'parsely', 'stats',
            
            # Advertising platforms
            'adsystem', 'adnxs', 'adserver', 'adsrvr', 'pubmatic', 'rubiconproject',
            'taboola', 'outbrain', 'criteo', 'mediamath', 'advertising.com', 
            
            # Tracking & fingerprinting
            'scorecardresearch', 'qualtrics', 'quantserve', 'trustarc', 'moatads',
            'mathtag', 'techtarget', 'fingerprint', 'muid', 'onetrust',
            
            # Social
            'facebook', 'fbcdn', 'twitter', 'linkedin', 'pinterest', 'tiktok',
            
            # Common tracking cookie domains
            'sharedid', 'rlcdn', 'bizible', 'demdex', 'optimizely', 'branch.io',
        ]
        
        # 2. CHECK KNOWN TRACKING DOMAINS
        for tracking_domain in expanded_tracking_domains:
            if tracking_domain in cookie_domain:
                return True, f"Domain contains known tracking pattern '{tracking_domain}'"
                
        # 3. CHECK TRACKING COOKIE NAMES
        tracking_cookie_names = [
            '_ga', '_gcl_au', '_fbp', '_scid', '_uetsid', '_uetvid', 
            'MUID', 'NID', '_sharedid', 'OptanonConsent', 'cf_clearance'
        ]
        
        if cookie_name in tracking_cookie_names:
            return True, f"Cookie name matches known tracking cookie '{cookie_name}'"
            
        # 4. ANALYZE SAME-SITE ATTRIBUTE
        if cookie.get('sameSite', -1) == 0:  # SameSite=None
            if cookie.get('secure', False):  # Secure SameSite=None cookies are typical of trackers
                return True, "SameSite=None and Secure attribute indicates third-party usage"
                
        # 5. DOMAIN STRUCTURE ANALYSIS - if domain has too many common subdomains with others, it's first-party
        for domain in all_domains:
            if cookie_domain == domain:
                return False, ""
            
            # Check if it's a subdomain of any principal domain
            if cookie_domain.endswith('.' + domain):
                return False, ""
                
            # Check if domains share the same base (e.g., google.com and analytics.google.com)
            parts1 = cookie_domain.split('.')
            parts2 = domain.split('.')
            
            # Check if they share the same base domain
            if len(parts1) >= 2 and len(parts2) >= 2:
                if parts1[-2:] == parts2[-2:]:
                    return False, ""
        
        # 6. SPECIAL CASES - KNOWN THIRD-PARTY SERVICES
        third_party_patterns = {
            'tracking': ['tracking', 'tracker', 'analytics', 'pixel', 'stat'],
            'advertising': ['ad', 'ads', 'advert', 'banner', 'sponsor', 'marketing'],
            'consent': ['consent', 'gdpr', 'ccpa', 'privacy', 'cookie-law'],
            'sharing': ['share', 'social', 'connect', 'widget']
        }
        
        # Check all patterns against the domain
        for category, patterns in third_party_patterns.items():
            for pattern in patterns:
                if pattern in cookie_domain.lower():
                    return True, f"Domain contains known third-party pattern '{pattern}'"
        
        # If domain doesn't match any first-party domain and doesn't follow subdomain patterns, it's most likely third-party
        return True, "Domain does not match any first-party domain and is likely third-party"