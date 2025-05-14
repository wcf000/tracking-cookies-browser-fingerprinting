"""
Cookie Extractor Module
Extracts cookies from browser databases.
"""

import os
import sqlite3
import json
import shutil
import platform
import time
from pathlib import Path
from datetime import datetime

class CookieExtractor:
    """Class to extract cookies from browser databases."""
    
    def __init__(self, browser='chrome', custom_path=None):
        """
        Initialize the cookie extractor.
        
        Args:
            browser (str): Browser to extract cookies from ('chrome', 'firefox', 'edge')
            custom_path (str, optional): Custom path to the cookie database file
        """
        self.browser = browser.lower()
        self.cookies = []
        self.cookie_db_path = custom_path
        
        # Only try to locate database if custom path not provided
        if not custom_path:
            self._locate_cookie_database()
        else:
            # Verify the custom path exists
            if not os.path.exists(custom_path):
                raise FileNotFoundError(f"Custom cookie database path not found: {custom_path}")
    
    def extract(self):
        """
        Extract cookies from the browser's database.
        
        Returns:
            list: List of extracted cookie dictionaries.
        """
        self.cookies = []
        
        try:
            # Get the cookie database path
            if not self.cookie_db_path:
                self.cookie_db_path = self._get_cookie_db_path()
            
            # Extract cookies based on browser type
            if self.browser == "chrome" or self.browser == "edge":
                self._extract_from_chrome()
            elif self.browser == "firefox":
                self._extract_from_firefox()
            else:
                raise ValueError(f"Unsupported browser: {self.browser}")
            
            print(f"Extracted {len(self.cookies)} cookies from {self.browser}")
            return self.cookies
            
        except Exception as e:
            print(f"Error extracting cookies: {e}")
            return []
    
    def save_to_json(self, output_file):
        """
        Save extracted cookies to a JSON file.
        
        Args:
            output_file (str): Path to save the cookies.
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.cookies, f, indent=2)
            print(f"Cookies saved to {output_file}")
            return True
        except Exception as e:
            print(f"Error saving cookies to JSON: {e}")
            return False
    
    def _locate_cookie_database(self):
        """Locate the cookie database path based on the browser and system."""
        self.cookie_db_path = self._get_cookie_db_path()
    
    def _get_cookie_db_path(self):
        """Get the path to the browser's cookie database."""
        system = platform.system()
        home = Path.home()
        
        if self.browser == "chrome":
            if system == "Windows":
                return home / "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
            elif system == "Darwin":
                return home / "Library/Application Support/Google/Chrome/Default/Cookies"
            else:
                return home / ".config/google-chrome/Default/Cookies"
        
        elif self.browser == "firefox":
            if system == "Windows":
                profiles_path = home / "AppData/Roaming/Mozilla/Firefox/Profiles"
            elif system == "Darwin":
                profiles_path = home / "Library/Application Support/Firefox/Profiles"
            else:
                profiles_path = home / ".mozilla/firefox"
            
            # Find the default profile or use the specified one
            if self.profile:
                profile_path = profiles_path / self.profile
                if not profile_path.exists():
                    raise FileNotFoundError(f"Firefox profile not found: {self.profile}")
                return profile_path / "cookies.sqlite"
            else:
                # Look for default profile
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
    
    def _extract_from_chrome(self):
        """Extract cookies from Chrome/Edge database."""
        temp_db = None
        
        try:
            # Make a temp copy of the database to avoid locked database issues
            temp_dir = Path.home() / ".cookie_extractor_temp"
            temp_dir.mkdir(exist_ok=True)
            temp_db = temp_dir / f"temp_{self.browser}_cookies.db"
            
            try:
                shutil.copy2(self.cookie_db_path, temp_db)
            except Exception as e:
                print(f"Warning: Could not create temp copy of cookie database: {e}")
                print("This may happen if the browser is running. Some cookies might not be accessible.")
                temp_db = self.cookie_db_path
            
            # Connect to the database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Try both Chrome schema
            try:
                cursor.execute("""
                SELECT host_key, name, value, path, expires_utc, is_secure, 
                       is_httponly, creation_utc, last_access_utc, 
                       has_expires, is_persistent, samesite, source_scheme
                FROM cookies
                """)
            except sqlite3.OperationalError:
                cursor.execute("""
                SELECT host_key, name, value, path, expires_utc, is_secure,
                       is_httponly, creation_utc, last_access_utc, 
                       has_expires, is_persistent
                FROM cookies
                """)
            for row in cursor.fetchall():
                cookie = {
                    "domain": row[0],
                    "name": row[1],
                    "value": row[2],
                    "path": row[3],
                    "expires": self._chrome_time_to_unix(row[4]) if row[4] else None,
                    "secure": bool(row[5]),
                    "httpOnly": bool(row[6]),
                    "created": self._chrome_time_to_unix(row[7]) if row[7] else None,
                    "lastAccessed": self._chrome_time_to_unix(row[8]) if row[8] else None,
                    "session": not bool(row[9]),
                    "persistent": bool(row[10]),
                    "sameSite": row[11] if len(row) > 11 else None,
                    "sourceScheme": row[12] if len(row) > 12 else None
                }
                self.cookies.append(cookie)
            conn.close() 
        except Exception as e:
            print(f"Error extracting cookies from {self.browser}: {e}") 
        finally:
            # Clean up temp file
            if temp_db and temp_db != self.cookie_db_path and os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass
    
    def _extract_from_firefox(self):
        """Extract cookies from Firefox database."""
        temp_db = None
        try:
            # Make a temp copy of the database
            temp_dir = Path.home() / ".cookie_extractor_temp"
            temp_dir.mkdir(exist_ok=True)
            temp_db = temp_dir / "temp_firefox_cookies.db"
            try:
                shutil.copy2(self.cookie_db_path, temp_db)
            except Exception as e:
                print(f"Warning: Could not create temp copy of cookie database: {e}")
                print("This may happen if the browser is running. Some cookies might not be accessible.")
                temp_db = self.cookie_db_path
            
            # Connect to the database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Firefox cookie schema
            cursor.execute("""
            SELECT host, name, value, path, expiry, isSecure, 
                   isHttpOnly, creationTime, lastAccessed
            FROM moz_cookies
            """)
            for row in cursor.fetchall():
                cookie = {
                    "domain": row[0],
                    "name": row[1],
                    "value": row[2],
                    "path": row[3],
                    "expires": row[4],
                    "secure": bool(row[5]),
                    "httpOnly": bool(row[6]),
                    "created": row[7] / 1000000 if row[7] else None,
                    "lastAccessed": row[8] / 1000000 if row[8] else None,
                    "session": row[4] == 0,
                    "persistent": row[4] != 0
                }
                self.cookies.append(cookie)
            conn.close()      
        except Exception as e:
            print(f"Error extracting cookies from Firefox: {e}")
        finally:
            # Clean up temp file
            if temp_db and temp_db != self.cookie_db_path and os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass
    
    def _chrome_time_to_unix(self, chrome_time):
        """
        Convert Chrome time format (microseconds since 1601-01-01) to Unix time.
        
        Args:
            chrome_time (int): Chrome timestamp
            
        Returns:
            float: Unix timestamp
        """
        if not chrome_time:
            return None
        return (chrome_time / 1000000) - 11644473600