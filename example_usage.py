#!/usr/bin/env python3
"""
Example usage scripts for the XSS Scanner
Demonstrates various scanning scenarios
"""

from xss_scanner import XSSScanner, InjectionContext


def example_1_basic_get_scan():
    """Basic GET request scan"""
    print("\n" + "="*80)
    print("Example 1: Basic GET Request Scan")
    print("="*80)
    
    scanner = XSSScanner()
    
    target_url = "http://testphp.vulnweb.com/search.php?test=query"
    parameters = ["test", "search"]
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
    ]
    
    results = scanner.scan_url(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='GET'
    )
    
    print(scanner.generate_report_terminal())
    scanner.generate_report_html("example1_report.html")


def example_2_post_scan():
    """POST request scan with form data"""
    print("\n" + "="*80)
    print("Example 2: POST Request Scan")
    print("="*80)
    
    scanner = XSSScanner()
    
    target_url = "http://example.com/contact"
    parameters = ["name", "email", "message"]
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
    ]
    
    # Additional POST data that should remain constant
    additional_data = {
        "csrf_token": "abc123xyz",
        "submit": "true"
    }
    
    results = scanner.scan_url(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='POST',
        data=additional_data
    )
    
    print(scanner.generate_report_terminal())


def example_3_attribute_name_focus():
    """Focus on attribute name injection"""
    print("\n" + "="*80)
    print("Example 3: Attribute Name Injection Testing")
    print("="*80)
    
    scanner = XSSScanner()
    
    target_url = "http://example.com/profile.php?id=123"
    parameters = ["attr", "class", "data-value"]
    
    # Only test attribute name context
    contexts = [InjectionContext.HTML_ATTRIBUTE_NAME]
    
    results = scanner.scan_url(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='GET'
    )
    
    print(scanner.generate_report_terminal())
    
    # Show which payloads were tested
    from xss_scanner import PayloadGenerator
    pg = PayloadGenerator()
    payloads = pg.generate_payloads(InjectionContext.HTML_ATTRIBUTE_NAME)
    
    print("\nPayloads tested for attribute name context:")
    for i, payload in enumerate(payloads, 1):
        print(f"  {i}. {payload}")


def example_4_parallel_scan():
    """Fast parallel scanning"""
    print("\n" + "="*80)
    print("Example 4: Parallel Scanning (Faster)")
    print("="*80)
    
    scanner = XSSScanner()
    
    target_url = "http://example.com/search.php"
    
    # More parameters to test
    parameters = ["q", "search", "query", "term", "keyword", "filter", "sort"]
    
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
        InjectionContext.JAVASCRIPT,
    ]
    
    import time
    start_time = time.time()
    
    results = scanner.scan_parallel(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='GET',
        max_workers=10  # Use 10 parallel threads
    )
    
    elapsed = time.time() - start_time
    
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds")
    print(scanner.generate_report_terminal())
    scanner.generate_report_html("example4_parallel_report.html")


def example_5_custom_headers_cookies():
    """Scan with authentication cookies and custom headers"""
    print("\n" + "="*80)
    print("Example 5: Authenticated Scan with Custom Headers")
    print("="*80)
    
    scanner = XSSScanner(user_agent="Mozilla/5.0 Custom Scanner")
    
    target_url = "http://example.com/dashboard"
    parameters = ["search", "filter"]
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
    ]
    
    # Custom headers
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }
    
    # Session cookies
    cookies = {
        "session": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user_id": "12345"
    }
    
    results = scanner.scan_url(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='GET',
        headers=headers,
        cookies=cookies
    )
    
    print(scanner.generate_report_terminal())


def example_6_all_contexts():
    """Test all available injection contexts"""
    print("\n" + "="*80)
    print("Example 6: Comprehensive Scan - All Contexts")
    print("="*80)
    
    scanner = XSSScanner()
    
    target_url = "http://testphp.vulnweb.com/search.php?test=query"
    parameters = ["test"]
    
    # Test ALL available contexts
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
        InjectionContext.HTML_TAG_NAME,
        InjectionContext.JAVASCRIPT,
        InjectionContext.SCRIPT_TAG,
        InjectionContext.URL_PARAM,
    ]
    
    print(f"\n[*] Testing {len(contexts)} different injection contexts...")
    
    results = scanner.scan_url(
        url=target_url,
        parameters=parameters,
        contexts=contexts,
        method='GET'
    )
    
    print(scanner.generate_report_terminal())
    scanner.generate_report_html("example6_comprehensive_report.html")
    
    # Show statistics
    print("\nContext Statistics:")
    from collections import Counter
    context_counts = Counter([r.context.value for r in results])
    for context, count in context_counts.items():
        print(f"  {context}: {count} reflection(s)")


def example_7_payload_showcase():
    """Showcase the payload generation for each context"""
    print("\n" + "="*80)
    print("Example 7: Payload Generator Showcase")
    print("="*80)
    
    from xss_scanner import PayloadGenerator
    
    pg = PayloadGenerator()
    
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
        InjectionContext.HTML_TAG_NAME,
        InjectionContext.JAVASCRIPT,
        InjectionContext.SCRIPT_TAG,
    ]
    
    for context in contexts:
        print(f"\n{context.value.upper()} Context Payloads:")
        print("-" * 80)
        payloads = pg.generate_payloads(context)
        for i, payload in enumerate(payloads, 1):
            print(f"  {i}. {payload}")


def main():
    """Run all examples"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          XSS Scanner - Examples                              ║
║                                                                              ║
║  This script demonstrates various usage scenarios of the XSS Scanner        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    examples = [
        ("Basic GET Scan", example_1_basic_get_scan),
        ("POST Request Scan", example_2_post_scan),
        ("Attribute Name Focus", example_3_attribute_name_focus),
        ("Parallel Scanning", example_4_parallel_scan),
        ("Authenticated Scan", example_5_custom_headers_cookies),
        ("All Contexts", example_6_all_contexts),
        ("Payload Showcase", example_7_payload_showcase),
    ]
    
    print("\nAvailable Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print("\n" + "="*80)
    choice = input("\nSelect example to run (1-7, or 'all' for all examples): ").strip()
    print("="*80)
    
    if choice.lower() == 'all':
        for name, func in examples:
            try:
                func()
                input("\nPress Enter to continue to next example...")
            except Exception as e:
                print(f"\n[!] Error in {name}: {e}")
    elif choice.isdigit() and 1 <= int(choice) <= len(examples):
        try:
            examples[int(choice)-1][1]()
        except Exception as e:
            print(f"\n[!] Error: {e}")
    else:
        print("[!] Invalid choice")


if __name__ == "__main__":
    main()
