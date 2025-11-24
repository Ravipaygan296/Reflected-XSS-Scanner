# Troubleshooting Guide

## Common Issues and Solutions

### Installation Issues

#### Problem: `ModuleNotFoundError: No module named 'requests'`
**Solution:**
```bash
pip install requests
# or
pip install -r requirements.txt
```

#### Problem: Permission denied when running script
**Solution:**
```bash
chmod +x xss_scanner.py
python3 xss_scanner.py  # or use python3 explicitly
```

---

### Scanning Issues

#### Problem: Connection timeout errors
**Symptoms:** `requests.exceptions.ConnectTimeout` or `requests.exceptions.ReadTimeout`

**Solutions:**
1. Increase timeout:
```python
scanner = XSSScanner(timeout=30)  # Increase from default 10
```

2. Check if target is accessible:
```bash
curl -I http://target-url.com
```

3. Check firewall/proxy settings

#### Problem: SSL Certificate verification failed
**Symptoms:** `requests.exceptions.SSLError`

**Solutions:**
1. For testing only, disable SSL verification (not recommended for production):
```python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# In scanner, modify session
scanner.session.verify = False
```

2. Better solution: Install proper certificates
```bash
pip install --upgrade certifi
```

#### Problem: Target returns 403 Forbidden
**Symptoms:** All requests return 403 status code

**Solutions:**
1. Add realistic User-Agent:
```python
scanner = XSSScanner(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
```

2. Check if authentication is required:
```python
cookies = {"session": "your-session-cookie"}
scanner.scan_url(url=target, parameters=params, contexts=contexts, cookies=cookies)
```

3. Rate limiting - add delays between requests

#### Problem: No reflections found but XSS should exist
**Symptoms:** Scanner completes but finds 0 reflections

**Solutions:**
1. Verify parameter names are correct:
```python
# Use browser dev tools to check actual parameter names
parameters = ["q", "search"]  # Make sure these match the actual form
```

2. Try different HTTP method:
```python
# If GET doesn't work, try POST
results = scanner.scan_url(url=target, parameters=params, contexts=contexts, method='POST')
```

3. Check if response is encoded differently:
```python
# Add debugging
response = scanner.session.get(url)
print(response.encoding)
print(response.text[:500])  # Check first 500 chars
```

4. Test with simpler payload first:
```python
# Manual test
import requests
r = requests.get("http://target.com/search?q=<script>alert(1)</script>")
print("<script>alert(1)</script>" in r.text)
```

---

### Report Generation Issues

#### Problem: HTML report not generated
**Symptoms:** No HTML file created or empty file

**Solutions:**
1. Check file permissions:
```bash
ls -la *.html
```

2. Specify full path:
```python
scanner.generate_report_html("/full/path/to/report.html")
```

3. Check disk space:
```bash
df -h
```

#### Problem: HTML report looks broken
**Symptoms:** Missing styling or garbled content

**Solutions:**
1. Check encoding:
```python
with open('report.html', 'r', encoding='utf-8') as f:
    content = f.read()
```

2. Open in different browser
3. Check if special characters are causing issues

---

### Performance Issues

#### Problem: Scanning is very slow
**Symptoms:** Takes minutes for small parameter list

**Solutions:**
1. Use parallel scanning:
```python
results = scanner.scan_parallel(
    url=target,
    parameters=params,
    contexts=contexts,
    max_workers=10  # Increase workers
)
```

2. Reduce number of contexts:
```python
# Instead of all contexts, use common ones
contexts = [
    InjectionContext.HTML_TEXT,
    InjectionContext.HTML_ATTRIBUTE_VALUE,
]
```

3. Test fewer parameters at once
4. Increase timeout if network is slow

#### Problem: Memory usage too high
**Symptoms:** Python process uses excessive RAM

**Solutions:**
1. Process results in batches
2. Clear results periodically:
```python
scanner.results = []  # Clear stored results
```

3. Reduce parallel workers:
```python
max_workers=3  # Instead of 10
```

---

### False Positive Issues

#### Problem: Too many false positives
**Symptoms:** Many reflections reported but not exploitable

**Solutions:**
1. Manually verify findings:
```python
# Check each result
for result in results:
    print(f"URL: {result.url}")
    print(f"Payload: {result.payload}")
    print(f"Snippet: {result.response_snippet}")
    print("---")
```

2. Check context in HTML report
3. Test in browser manually
4. Look for encoding that prevents execution

#### Problem: Known XSS not detected
**Symptoms:** Scanner misses obvious XSS

**Solutions:**
1. Check if using correct context:
```python
# Try all contexts
contexts = list(InjectionContext)
```

2. Check detection logic:
```python
# Test manually
payload = "<script>test</script>"
response_text = "... <script>test</script> ..."
is_reflected = scanner._is_reflected(payload, response_text)
print(f"Detected: {is_reflected}")
```

3. Add custom payloads:
```python
class CustomPayloadGen(PayloadGenerator):
    def _html_text_payloads(self):
        return ["<your-custom-payload>"]
```

---

### Testing Issues

#### Problem: Unit tests fail
**Symptoms:** `test_xss_scanner.py` reports failures

**Solutions:**
1. Check dependencies:
```bash
pip install -r requirements.txt
```

2. Run specific test:
```bash
python -m unittest test_xss_scanner.TestPayloadGenerator.test_marker_exists
```

3. Check Python version:
```bash
python --version  # Should be 3.7+
```

#### Problem: Import errors in tests
**Symptoms:** `ModuleNotFoundError` when running tests

**Solutions:**
1. Ensure script is in same directory:
```bash
ls
# Should show: xss_scanner.py, test_xss_scanner.py
```

2. Run from correct directory:
```bash
cd /path/to/xss-scanner
python test_xss_scanner.py
```

---

### Authentication Issues

#### Problem: Session expires during scan
**Symptoms:** First few requests succeed, then get 401/403

**Solutions:**
1. Refresh session before scan
2. Use long-lived session token
3. Add session refresh logic:
```python
# Re-authenticate if needed
if response.status_code == 401:
    # Refresh session
    pass
```

#### Problem: Can't authenticate with cookies
**Symptoms:** Authentication doesn't work with provided cookies

**Solutions:**
1. Check cookie format:
```python
# Cookies should be dict
cookies = {"session_id": "value", "user": "name"}
```

2. Check if domain-specific:
```python
# Some cookies are domain-specific
scanner.session.cookies.set("name", "value", domain=".example.com")
```

3. Export cookies from browser:
- Use browser extension to export cookies
- Convert to Python dict format

---

### Platform-Specific Issues

#### Windows Issues

**Problem:** Path separators cause issues
```python
# Use forward slashes or raw strings
report_path = r"C:\Users\Name\report.html"
# or
report_path = "C:/Users/Name/report.html"
```

**Problem:** Encoding issues
```python
# Specify encoding explicitly
with open('report.html', 'w', encoding='utf-8') as f:
    f.write(content)
```

#### Linux/Mac Issues

**Problem:** Permission denied
```bash
chmod +x xss_scanner.py
# or use python3 explicitly
python3 xss_scanner.py
```

**Problem:** Multiple Python versions
```bash
# Use python3 explicitly
python3 -m pip install requests
python3 xss_scanner.py
```

---

## Debugging Tips

### Enable Verbose Logging

Add to your script:
```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# In scanner
logger.debug(f"Testing payload: {payload}")
logger.debug(f"Response status: {response.status_code}")
```

### Test Single Payload Manually

```python
from xss_scanner import XSSScanner, InjectionContext

scanner = XSSScanner()
payload = "<script>alert('test')</script>"

# Test specific payload
result = scanner._test_payload(
    url="http://example.com/search?q=test",
    parameter="q",
    payload=payload,
    context=InjectionContext.HTML_TEXT,
    method='GET',
    data=None,
    headers=None,
    cookies=None
)

print(result)
```

### Check Raw Response

```python
import requests

response = requests.get("http://example.com/search?q=<test>")
print(f"Status: {response.status_code}")
print(f"Headers: {response.headers}")
print(f"Body: {response.text[:1000]}")  # First 1000 chars
```

### Verify Payload Generation

```python
from xss_scanner import PayloadGenerator, InjectionContext

gen = PayloadGenerator()
payloads = gen.generate_payloads(InjectionContext.HTML_ATTRIBUTE_NAME)

for i, payload in enumerate(payloads, 1):
    print(f"{i}. {payload}")
```

---

## Getting Help

If you still have issues:

1. **Check GitHub Issues**: See if someone else had the same problem
2. **Create Issue**: Include:
   - Python version
   - Error message (full traceback)
   - Code that reproduces the issue
   - Operating system
3. **Provide Context**: What were you trying to do?
4. **Minimal Example**: Reduce to smallest code that shows the problem

---

## Best Practices to Avoid Issues

1. **Always test with known vulnerable app first**
2. **Start with simple payloads and contexts**
3. **Use try-except for error handling**
4. **Check response status codes**
5. **Verify target is accessible before scanning**
6. **Use appropriate timeout values**
7. **Read documentation thoroughly**
8. **Keep dependencies updated**

---

## Quick Diagnostic Checklist

Before reporting an issue, check:

- [ ] Python version is 3.7 or higher
- [ ] All dependencies installed (`pip list`)
- [ ] Target URL is accessible (use browser/curl)
- [ ] Parameter names are correct
- [ ] File permissions are correct
- [ ] Sufficient disk space
- [ ] No firewall blocking requests
- [ ] Authentication works (if needed)
- [ ] Read error message carefully
- [ ] Tried simplest possible example

---

**Remember**: Most issues are due to network problems, wrong parameters, or missing authentication. Double-check the basics first!
