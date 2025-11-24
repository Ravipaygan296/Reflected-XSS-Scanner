# Reflected-XSS-Scanner
**# Reflected XSS Scanner

A Python-based tool for detecting reflected Cross-Site Scripting (XSS) vulnerabilities with context-aware payload generation.

## 🎯 Overview

This scanner identifies reflected XSS vulnerabilities by:
- Injecting context-specific payloads into URL parameters
- Detecting payload reflections in HTTP responses
- Supporting multiple injection contexts including attribute names
- Generating comprehensive HTML and terminal reports

## 🏗️ Architecture

### Core Components

#### 1. PayloadGenerator Class
The `PayloadGenerator` is the heart of the scanner's intelligence. It generates payloads tailored to specific injection contexts:

**How it works:**
- Each injection context requires different escape/breaking techniques
- Payloads are crafted to bypass encoding and execute in that specific context
- Includes a unique marker (`XSSTEST`) to identify reflections

**Supported Contexts:**
1. **HTML_TEXT** - Content between HTML tags
   - Uses: `<script>`, `<img>`, `<svg>` tags
   - Example: `<script>alert('XSSTEST')</script>`

2. **HTML_ATTRIBUTE_VALUE** - Inside attribute values like `<img src="HERE">`
   - Breaks out with quotes: `' onload=alert('XSSTEST') '`
   - Closes tags: `"><script>alert('XSSTEST')</script>`

3. **HTML_ATTRIBUTE_NAME** - As the attribute name itself `<img HERE>`
   - Critical context requiring event handlers
   - Examples: `onload=alert('XSSTEST')`, `onfocus=alert('XSSTEST') autofocus`
   - Often paired with auto-triggering attributes

4. **HTML_TAG_NAME** - Inside tag names `<HERE>`
   - Completes the tag with payload
   - Example: `script>alert('XSSTEST')</script>`

5. **JAVASCRIPT** - Inside JavaScript code blocks
   - Breaks out of strings/context
   - Example: `';alert('XSSTEST');//`

6. **SCRIPT_TAG** - Inside `<script>` tags
   - Closes script and injects new one
   - Example: `</script><script>alert('XSSTEST')</script>`

#### 2. XSSScanner Class
Orchestrates the scanning process:
- Sends HTTP requests (GET/POST)
- Manages payload injection
- Detects reflections using multiple detection methods
- Generates reports

#### 3. Reflection Detection
Multi-layered detection approach:
- **Direct matching**: Checks if payload appears as-is
- **HTML-encoded**: Checks `html.escape()` version
- **URL-encoded**: Checks `urllib.parse.quote()` version

This handles cases where the application applies encoding but the payload is still reflected.

### Design Choices

**1. Dataclass for Results**
- Uses Python dataclasses for clean, type-safe result storage
- Easy serialization for reporting

**2. Session Management**
- Uses `requests.Session()` for connection pooling
- Improves performance on multiple requests to same host

**3. Enum for Contexts**
- Type-safe context specification
- Easy to extend with new contexts

**4. Parallel Scanning**
- Optional ThreadPoolExecutor for concurrent testing
- Configurable worker threads
- Improves scan speed significantly

## 📋 Requirements

- Python 3.7+
- requests library

## 🚀 Installation & Setup

```bash
# Clone the repository
git clone https:https://github.com/Ravipaygan296/Reflected-XSS-Scanner
cd xss-scanner

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x xss_scanner.py
```

**requirements.txt:**
```
requests>=2.28.0
```

## 💻 Usage

### Basic Usage

```python
from xss_scanner import XSSScanner, InjectionContext

# Initialize scanner
scanner = XSSScanner(timeout=10)

# Define target
target_url = "http://example.com/search.php"
parameters = ["q", "search", "query"]

# Define contexts to test
contexts = [
    InjectionContext.HTML_TEXT,
    InjectionContext.HTML_ATTRIBUTE_VALUE,
    InjectionContext.HTML_ATTRIBUTE_NAME,
    InjectionContext.JAVASCRIPT,
]

# Perform scan
results = scanner.scan_url(
    url=target_url,
    parameters=parameters,
    contexts=contexts,
    method='GET'
)

# Generate reports
print(scanner.generate_report_terminal())
scanner.generate_report_html("report.html")
```

### Advanced Usage

**POST Request with Custom Headers:**
```python
scanner = XSSScanner(user_agent="Custom-Agent/1.0")

results = scanner.scan_url(
    url="http://example.com/login",
    parameters=["username", "email"],
    contexts=[InjectionContext.HTML_TEXT, InjectionContext.HTML_ATTRIBUTE_VALUE],
    method='POST',
    data={"password": "test123"},
    headers={"X-Custom-Header": "value"},
    cookies={"session": "abc123"}
)
```

**Parallel Scanning:**
```python
# Faster scanning with multiple threads
results = scanner.scan_parallel(
    url=target_url,
    parameters=parameters,
    contexts=contexts,
    method='GET',
    max_workers=10  # Number of parallel threads
)
```

### Command Line Usage

Run the example in the script:
```bash
python xss_scanner.py
```

## 📊 Report Formats

### Terminal Report
- Compact, readable format
- Shows all findings with key details
- Perfect for quick analysis

### HTML Report
- Professional, styled HTML document
- Color-coded findings
- Includes response snippets
- Shareable with team members

## 🔍 Testing Multiple Contexts

The scanner tests each parameter against all specified contexts:

```python
# Test attribute-name context specifically
results = scanner.scan_url(
    url="http://example.com/page",
    parameters=["attr"],
    contexts=[InjectionContext.HTML_ATTRIBUTE_NAME],
    method='GET'
)

# The scanner will try payloads like:
# - onload=alert('XSSTEST')
# - onfocus=alert('XSSTEST') autofocus
# - onerror=alert('XSSTEST') src=x
```

## 🎯 Assumptions & Limitations

### Assumptions
1. **Target is accessible**: The scanner assumes the target URL is reachable
2. **HTTP/HTTPS only**: Currently supports HTTP(S) protocols
3. **UTF-8 encoding**: Assumes UTF-8 response encoding
4. **Reflection = vulnerability**: Any reflection is flagged (may include false positives)

### Limitations
1. **No DOM-based XSS detection**: Only detects reflected (server-side) XSS
2. **Simple detection**: Uses substring matching, may miss complex encoding scenarios
3. **No authentication bypass**: Requires valid session if authentication is needed
4. **Rate limiting**: May trigger rate limits on target servers
5. **No WAF evasion**: Basic payloads without advanced filter bypass

### What's NOT Included (But Could Be Added)
- Blind XSS detection (requires callback server)
- Mutation-based fuzzing
- DOM XSS analysis
- Advanced WAF bypass techniques
- Browser verification of exploitation

## 🔒 Ethical Use & Legal Notice

**⚠️ IMPORTANT: This tool is for authorized security testing only.**

- Only test systems you own or have explicit permission to test
- Unauthorized testing may be illegal in your jurisdiction
- Always follow responsible disclosure practices
- Not responsible for misuse of this tool

## 🛠️ Code Quality & Design

### Design Principles
1. **Separation of Concerns**: PayloadGenerator, Scanner, and Reporter are separate
2. **Extensibility**: Easy to add new contexts and payload types
3. **Type Safety**: Uses type hints and enums throughout
4. **Clean Code**: PEP 8 compliant, well-documented
5. **Error Handling**: Graceful handling of network errors

### Testing Considerations
- Modular design allows unit testing of components
- PayloadGenerator can be tested independently
- Reflection detection logic is isolated

## 📈 Future Enhancements

Potential improvements:
- [ ] DOM XSS detection via headless browser
- [ ] Machine learning for context auto-detection
- [ ] WAF fingerprinting and bypass payloads
- [ ] Blind XSS with callback server
- [ ] CSV/JSON export formats
- [ ] Configurable payload templates via YAML
- [ ] Mutation-based fuzzing
- [ ] Integration with Burp Suite/OWASP ZAP

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## 👤 Author
Ravi rajendra payghan
Created for VipraTech Security Engineer assignment

## 📞 Contact

For questions about this implementation, create an issue on GitHub.

---

**Note**: This is a security testing tool. Always obtain proper authorization before testing any system.**
