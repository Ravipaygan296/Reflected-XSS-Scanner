# Quick Start Guide - XSS Scanner

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Basic Scan
```python
from xss_scanner import XSSScanner, InjectionContext

# Create scanner
scanner = XSSScanner()

# Scan a URL
results = scanner.scan_url(
    url="http://example.com/search.php?q=test",
    parameters=["q"],
    contexts=[
        InjectionContext.HTML_TEXT,
        InjectionContext.HTML_ATTRIBUTE_VALUE,
        InjectionContext.HTML_ATTRIBUTE_NAME
    ],
    method='GET'
)

# View results
print(scanner.generate_report_terminal())
scanner.generate_report_html()
```

### Step 3: Run Examples
```bash
python example_usage.py
```

## 📝 Common Use Cases

### Scan a Form
```python
scanner = XSSScanner()

results = scanner.scan_url(
    url="http://example.com/contact",
    parameters=["name", "email", "message"],
    contexts=[InjectionContext.HTML_TEXT, InjectionContext.HTML_ATTRIBUTE_VALUE],
    method='POST',
    data={"submit": "true"}
)
```

### Authenticated Scan
```python
scanner = XSSScanner()

results = scanner.scan_url(
    url="http://example.com/dashboard",
    parameters=["search"],
    contexts=[InjectionContext.HTML_TEXT],
    method='GET',
    cookies={"session": "your-session-cookie"}
)
```

### Fast Parallel Scan
```python
results = scanner.scan_parallel(
    url="http://example.com/search.php",
    parameters=["q", "filter", "sort"],
    contexts=[InjectionContext.HTML_TEXT, InjectionContext.HTML_ATTRIBUTE_NAME],
    method='GET',
    max_workers=10
)
```

## 🎯 Test Attribute Name Context

The attribute name context is particularly interesting:

```python
scanner = XSSScanner()

# Focus on attribute name injection
results = scanner.scan_url(
    url="http://example.com/page.php?attr=test",
    parameters=["attr"],
    contexts=[InjectionContext.HTML_ATTRIBUTE_NAME],
    method='GET'
)

# This tests payloads like:
# - onload=alert('XSSTEST')
# - onfocus=alert('XSSTEST') autofocus
# - onerror=alert('XSSTEST') src=x
```

## 📊 Understanding Reports

### Terminal Report
Shows:
- Finding number
- URL and parameter
- HTTP method
- Injection context
- Successful payload
- Response snippet

### HTML Report
Professional format with:
- Color-coded findings
- Full details
- Easy to share
- Save and archive

## ⚠️ Important Notes

1. **Authorization Required**: Only test systems you own or have permission to test
2. **Not for Production**: This is a testing tool, not for attacking live sites
3. **False Positives**: Some reflections may not be exploitable - verify manually
4. **Rate Limiting**: May trigger rate limits, consider adding delays

## 🐛 Troubleshooting

**Connection errors?**
- Check URL is correct and accessible
- Verify firewall settings
- Try increasing timeout

**No reflections found?**
- Try different contexts
- Check if WAF is blocking
- Verify parameter names are correct

**Too slow?**
- Use parallel scanning
- Reduce number of contexts
- Increase timeout value

## 📚 Next Steps

- Read [README.md](README.md) for full documentation
- Check [ARCHITECTURE.md](ARCHITECTURE.md) for design details
- Explore [example_usage.py](example_usage.py) for more examples
- Run tests with `python test_xss_scanner.py`

## 💡 Tips

1. **Start simple**: Test one parameter with HTML_TEXT first
2. **Add contexts gradually**: Once basic scan works, add more contexts
3. **Use parallel for many params**: Saves time on large scans
4. **Check HTML reports**: Easier to analyze than terminal output
5. **Verify findings**: Always manually verify XSS is exploitable

## 🎓 Learning Resources

To understand XSS better:
- OWASP XSS Guide
- PortSwigger Web Security Academy
- HackerOne disclosed reports

## 📞 Support

Found a bug? Have a question?
- Open an issue on GitHub
- Check existing issues first
- Provide example URLs (if safe to share)

---

Happy (ethical) hacking! 🔒
