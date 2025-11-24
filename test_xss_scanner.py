#!/usr/bin/env python3
"""
Unit tests for XSS Scanner
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from xss_scanner import (
    PayloadGenerator,
    XSSScanner,
    InjectionContext,
    ReflectionResult
)


class TestPayloadGenerator(unittest.TestCase):
    """Test PayloadGenerator class"""
    
    def setUp(self):
        self.generator = PayloadGenerator()
    
    def test_marker_exists(self):
        """Test that marker is set"""
        self.assertEqual(self.generator.marker, "XSSTEST")
    
    def test_html_text_payloads(self):
        """Test HTML text context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.HTML_TEXT)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Check that payloads contain marker
        for payload in payloads:
            self.assertIn("XSSTEST", payload)
    
    def test_attribute_value_payloads(self):
        """Test HTML attribute value context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.HTML_ATTRIBUTE_VALUE)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Should contain quote-breaking payloads
        has_quote_break = any("'" in p or '"' in p for p in payloads)
        self.assertTrue(has_quote_break)
    
    def test_attribute_name_payloads(self):
        """Test HTML attribute name context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.HTML_ATTRIBUTE_NAME)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Should contain event handlers
        has_event_handler = any(
            "onload" in p or "onfocus" in p or "onerror" in p 
            for p in payloads
        )
        self.assertTrue(has_event_handler)
    
    def test_tag_name_payloads(self):
        """Test HTML tag name context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.HTML_TAG_NAME)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_javascript_payloads(self):
        """Test JavaScript context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.JAVASCRIPT)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Should contain string-breaking payloads
        has_string_break = any("';" in p or '"' in p for p in payloads)
        self.assertTrue(has_string_break)
    
    def test_script_tag_payloads(self):
        """Test script tag context payloads"""
        payloads = self.generator.generate_payloads(InjectionContext.SCRIPT_TAG)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_all_contexts_return_payloads(self):
        """Test that all contexts return payloads"""
        for context in InjectionContext:
            payloads = self.generator.generate_payloads(context)
            self.assertIsInstance(payloads, list)
            self.assertGreater(len(payloads), 0, 
                             f"Context {context.value} returned no payloads")


class TestXSSScanner(unittest.TestCase):
    """Test XSSScanner class"""
    
    def setUp(self):
        self.scanner = XSSScanner(timeout=5)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner.session)
        self.assertIsInstance(self.scanner.payload_generator, PayloadGenerator)
        self.assertEqual(self.scanner.timeout, 5)
        self.assertEqual(len(self.scanner.results), 0)
    
    def test_custom_user_agent(self):
        """Test custom user agent setting"""
        custom_ua = "TestScanner/1.0"
        scanner = XSSScanner(user_agent=custom_ua)
        self.assertEqual(scanner.session.headers['User-Agent'], custom_ua)
    
    def test_is_reflected_direct_match(self):
        """Test direct payload reflection detection"""
        payload = "<script>alert('test')</script>"
        response_text = f"Search results for: {payload}"
        self.assertTrue(self.scanner._is_reflected(payload, response_text))
    
    def test_is_reflected_html_encoded(self):
        """Test HTML-encoded payload detection"""
        payload = "<script>alert('test')</script>"
        response_text = "Search results for: &lt;script&gt;alert(&#x27;test&#x27;)&lt;/script&gt;"
        self.assertTrue(self.scanner._is_reflected(payload, response_text))
    
    def test_is_not_reflected(self):
        """Test when payload is not reflected"""
        payload = "<script>alert('test')</script>"
        response_text = "No results found"
        self.assertFalse(self.scanner._is_reflected(payload, response_text))
    
    def test_extract_snippet(self):
        """Test snippet extraction"""
        payload = "TESTPAYLOAD"
        response_text = "Some text before " + payload + " some text after"
        snippet = self.scanner._extract_snippet(response_text, payload, context_size=10)
        self.assertIn(payload, snippet)
        self.assertIn("...", snippet)
    
    @patch('requests.Session.get')
    def test_scan_url_get(self, mock_get):
        """Test GET request scanning"""
        # Mock response
        mock_response = Mock()
        mock_response.text = "<html><body><script>alert('XSSTEST')</script></body></html>"
        mock_get.return_value = mock_response
        
        results = self.scanner.scan_url(
            url="http://example.com/test",
            parameters=["q"],
            contexts=[InjectionContext.HTML_TEXT],
            method='GET'
        )
        
        self.assertIsInstance(results, list)
        mock_get.assert_called()
    
    @patch('requests.Session.post')
    def test_scan_url_post(self, mock_post):
        """Test POST request scanning"""
        # Mock response
        mock_response = Mock()
        mock_response.text = "<html><body>No reflection</body></html>"
        mock_post.return_value = mock_response
        
        results = self.scanner.scan_url(
            url="http://example.com/submit",
            parameters=["name"],
            contexts=[InjectionContext.HTML_TEXT],
            method='POST',
            data={"other": "value"}
        )
        
        self.assertIsInstance(results, list)
        mock_post.assert_called()
    
    def test_generate_report_terminal_no_results(self):
        """Test terminal report with no results"""
        report = self.scanner.generate_report_terminal()
        self.assertIn("No reflections detected", report)
    
    def test_generate_report_terminal_with_results(self):
        """Test terminal report with results"""
        # Add a mock result
        result = ReflectionResult(
            url="http://example.com",
            parameter="test",
            payload="<script>alert('x')</script>",
            context=InjectionContext.HTML_TEXT,
            reflected_position="...<script>alert('x')</script>...",
            method="GET",
            response_snippet="...<script>alert('x')</script>..."
        )
        self.scanner.results.append(result)
        
        report = self.scanner.generate_report_terminal()
        self.assertIn("XSS SCANNER RESULTS", report)
        self.assertIn("http://example.com", report)
        self.assertIn("test", report)
    
    def test_generate_report_html(self):
        """Test HTML report generation"""
        import os
        output_file = "test_report.html"
        
        # Clean up if exists
        if os.path.exists(output_file):
            os.remove(output_file)
        
        try:
            self.scanner.generate_report_html(output_file)
            self.assertTrue(os.path.exists(output_file))
            
            # Check content
            with open(output_file, 'r') as f:
                content = f.read()
                self.assertIn("XSS Scanner Report", content)
                self.assertIn("<!DOCTYPE html>", content)
        finally:
            # Clean up
            if os.path.exists(output_file):
                os.remove(output_file)


class TestReflectionResult(unittest.TestCase):
    """Test ReflectionResult dataclass"""
    
    def test_reflection_result_creation(self):
        """Test creating a ReflectionResult"""
        result = ReflectionResult(
            url="http://example.com",
            parameter="q",
            payload="<script>test</script>",
            context=InjectionContext.HTML_TEXT,
            reflected_position="...<script>test</script>...",
            method="GET",
            response_snippet="snippet here"
        )
        
        self.assertEqual(result.url, "http://example.com")
        self.assertEqual(result.parameter, "q")
        self.assertEqual(result.method, "GET")
        self.assertEqual(result.context, InjectionContext.HTML_TEXT)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    @patch('requests.Session.get')
    def test_full_scan_workflow(self, mock_get):
        """Test complete scanning workflow"""
        # Mock response with reflection
        mock_response = Mock()
        mock_response.text = """
        <html>
            <body>
                <div>Search: <script>alert('XSSTEST')</script></div>
            </body>
        </html>
        """
        mock_get.return_value = mock_response
        
        # Create scanner and scan
        scanner = XSSScanner()
        results = scanner.scan_url(
            url="http://example.com/search",
            parameters=["q"],
            contexts=[InjectionContext.HTML_TEXT],
            method='GET'
        )
        
        # Verify results
        self.assertGreater(len(results), 0)
        
        # Generate reports
        terminal_report = scanner.generate_report_terminal()
        self.assertIn("XSS SCANNER RESULTS", terminal_report)
        
        # Test HTML report
        import os
        html_file = "test_integration_report.html"
        try:
            scanner.generate_report_html(html_file)
            self.assertTrue(os.path.exists(html_file))
        finally:
            if os.path.exists(html_file):
                os.remove(html_file)


def run_tests():
    """Run all tests"""
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == "__main__":
    print("="*80)
    print("Running XSS Scanner Test Suite")
    print("="*80)
    run_tests()
