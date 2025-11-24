# XSS Scanner - Architecture & Design Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Payload Generation Strategy](#payload-generation-strategy)
4. [Context Detection](#context-detection)
5. [Reflection Detection](#reflection-detection)
6. [Design Decisions](#design-decisions)
7. [Performance Considerations](#performance-considerations)
8. [Security Considerations](#security-considerations)

## Overview

This XSS scanner is built with a modular, extensible architecture that separates concerns between payload generation, HTTP request handling, reflection detection, and reporting.

### High-Level Flow
```
User Input → Scanner → PayloadGenerator → HTTP Client → Response Analysis → Report
```

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         XSSScanner                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  PayloadGenerator                     │  │
│  │  - Context-aware payload generation                   │  │
│  │  - Dynamic payload adaptation                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                           ↓                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  Request Handler                      │  │
│  │  - GET/POST support                                   │  │
│  │  - Session management                                 │  │
│  │  - Custom headers/cookies                             │  │
│  └───────────────────────────────────────────────────────┘  │
│                           ↓                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │               Reflection Detector                     │  │
│  │  - Multi-layered detection                            │  │
│  │  - Encoding-aware matching                            │  │
│  └───────────────────────────────────────────────────────┘  │
│                           ↓                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  Report Generator                     │  │
│  │  - Terminal output                                    │  │
│  │  - HTML reports                                       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Class Structure

#### 1. InjectionContext (Enum)
- **Purpose**: Type-safe context identification
- **Values**: 
  - HTML_TEXT
  - HTML_ATTRIBUTE_VALUE
  - HTML_ATTRIBUTE_NAME
  - HTML_TAG_NAME
  - JAVASCRIPT
  - SCRIPT_TAG
  - URL_PARAM

**Why Enum?**
- Prevents typos and invalid contexts
- IDE autocomplete support
- Easy to extend
- Type checking at development time

#### 2. ReflectionResult (Dataclass)
- **Purpose**: Structured storage of findings
- **Fields**:
  - `url`: Target URL
  - `parameter`: Vulnerable parameter
  - `payload`: Successful payload
  - `context`: Injection context
  - `reflected_position`: Where in response
  - `method`: HTTP method used
  - `response_snippet`: Context around reflection

**Why Dataclass?**
- Automatic `__init__`, `__repr__`, `__eq__`
- Type hints support
- Immutable (with `frozen=True` if needed)
- Clean serialization

#### 3. PayloadGenerator
**Responsibility**: Generate context-aware XSS payloads

**Key Methods**:
- `generate_payloads(context)`: Main entry point
- `_html_text_payloads()`: HTML content payloads
- `_attribute_value_payloads()`: Attribute escaping
- `_attribute_name_payloads()`: Event handler injection
- `_tag_name_payloads()`: Tag breaking
- `_javascript_payloads()`: JavaScript context escaping
- `_script_tag_payloads()`: Script tag context

**Design Pattern**: Strategy Pattern
- Each context has its own strategy method
- Easy to add new contexts
- Testable in isolation

#### 4. XSSScanner
**Responsibility**: Orchestrate scanning process

**Key Methods**:
- `scan_url()`: Single-threaded scan
- `scan_parallel()`: Multi-threaded scan
- `_test_payload()`: Individual payload test
- `_is_reflected()`: Reflection detection
- `generate_report_terminal()`: Console output
- `generate_report_html()`: HTML output

## Payload Generation Strategy

### Context-Specific Approach

The scanner uses a **context-aware payload generation** strategy. Different injection contexts require different escape techniques:

#### 1. HTML Text Context
```html
<div>USER_INPUT</div>
```

**Challenge**: Need to inject HTML tags
**Strategy**: Use complete HTML tags
```html
<script>alert('XSSTEST')</script>
<img src=x onerror=alert('XSSTEST')>
```

#### 2. HTML Attribute Value Context
```html
<input value="USER_INPUT">
```

**Challenge**: Escape from attribute quotes
**Strategy**: Quote breaking + event handlers
```html
" onload=alert("XSSTEST") "
"><script>alert('XSSTEST')</script>
```

#### 3. HTML Attribute Name Context ⭐
```html
<img USER_INPUT="value">
```

**Challenge**: Payload becomes the attribute itself
**Strategy**: Event handlers that auto-trigger
```html
onload=alert('XSSTEST')
onfocus=alert('XSSTEST') autofocus
onerror=alert('XSSTEST') src=x
```

**Why this works**:
- `onload` fires when image loads
- `onfocus` + `autofocus` fires immediately
- `onerror` + invalid `src` fires immediately

#### 4. HTML Tag Name Context
```html
<USER_INPUT>
```

**Challenge**: Complete the tag and inject
**Strategy**: Close tag and inject new content
```html
script>alert('XSSTEST')</script><x
img src=x onerror=alert('XSSTEST')><x
```

#### 5. JavaScript Context
```javascript
var x = "USER_INPUT";
```

**Challenge**: Break out of JavaScript strings
**Strategy**: String termination + statement injection
```javascript
";alert("XSSTEST");//
'-alert('XSSTEST')-'
```

#### 6. Script Tag Context
```html
<script>var x = "USER_INPUT";</script>
```

**Challenge**: Already in JavaScript
**Strategy**: Close script, inject new script
```html
</script><script>alert('XSSTEST')</script><script>
```

### Payload Characteristics

All payloads include:
1. **Marker**: `XSSTEST` for easy detection
2. **Self-contained**: Work without external dependencies
3. **Non-destructive**: Use `alert()` for testing
4. **Context-specific**: Tailored to bypass context constraints

## Context Detection

### Current Approach: User-Specified
Users specify which contexts to test:
```python
contexts = [
    InjectionContext.HTML_TEXT,
    InjectionContext.HTML_ATTRIBUTE_NAME,
]
```

### Future Enhancement: Auto-Detection

Potential algorithm:
1. Send probe payloads to identify context
2. Parse HTML/JavaScript response
3. Locate reflection position
4. Determine surrounding syntax
5. Select appropriate payloads

**Example**:
```python
def detect_context(response, marker):
    """Auto-detect injection context"""
    # Find marker in response
    soup = BeautifulSoup(response, 'html.parser')
    
    # Check if in tag
    if soup.find(attrs={marker: True}):
        return InjectionContext.HTML_ATTRIBUTE_NAME
    
    # Check if in attribute value
    for tag in soup.find_all():
        for attr, value in tag.attrs.items():
            if marker in str(value):
                return InjectionContext.HTML_ATTRIBUTE_VALUE
    
    # Check if in text
    if marker in soup.get_text():
        return InjectionContext.HTML_TEXT
    
    return InjectionContext.GENERIC
```

## Reflection Detection

### Multi-Layered Approach

The scanner uses **three detection layers** to catch reflections regardless of encoding:

#### Layer 1: Direct Match
```python
if payload in response_text:
    return True
```
Catches unfiltered reflections.

#### Layer 2: HTML-Encoded Match
```python
encoded = html.escape(payload)
if encoded in response_text:
    return True
```
Catches HTML entity encoding:
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `'` → `&#x27;`

#### Layer 3: URL-Encoded Match
```python
url_encoded = urllib.parse.quote(payload)
if url_encoded in response_text:
    return True
```
Catches URL encoding:
- `<` → `%3C`
- `>` → `%3E`
- ` ` → `%20`

### Why Multiple Layers?

Real-world applications apply various encoding schemes:
- **Security filters**: HTML entity encoding
- **URL reflections**: URL encoding
- **JSON responses**: Unicode escaping
- **JavaScript**: Backslash escaping

Multiple layers ensure we catch reflections even when encoded.

### False Positive Consideration

**Trade-off**: More layers = more detections but potentially more false positives

**Mitigation**:
- Manual verification recommended
- Context snippet helps identify false positives
- Future: Add confirmation checks

## Design Decisions

### 1. Why Python?
- **Rapid development**: Quick prototyping
- **Rich libraries**: requests, urllib, html
- **Readability**: Clean, maintainable code
- **Community**: Large security testing ecosystem

### 2. Why requests Library?
- **Session management**: Connection pooling
- **Easy interface**: Simpler than urllib
- **Features**: Cookies, headers, redirects handled automatically
- **Stability**: Battle-tested, widely used

### 3. Why Synchronous by Default?
- **Simplicity**: Easier to understand and debug
- **Reliability**: Fewer race conditions
- **Optional async**: Can add threading when needed

### 4. Why Simple String Matching?
**Pros**:
- Fast and efficient
- Works for most cases
- Easy to understand

**Cons**:
- May miss complex encoding
- No DOM parsing

**Decision**: Start simple, can enhance later with:
- HTML parsing (BeautifulSoup)
- JavaScript execution (Selenium)
- Headless browser (Playwright)

### 5. Why Both Terminal and HTML Reports?
- **Terminal**: Quick feedback during scan
- **HTML**: Shareable, professional, persistent
- **Flexibility**: Users choose preferred format

### 6. Code Organization

**Single file vs. Multi-file**:
- **Choice**: Single file for simplicity
- **Reasoning**: 
  - Easy to share and understand
  - All code in one place
  - Can split later if needed

**Future refactoring**:
```
xss_scanner/
├── __init__.py
├── core/
│   ├── scanner.py
│   ├── payloads.py
│   └── detector.py
├── reports/
│   ├── terminal.py
│   └── html.py
└── utils/
    └── helpers.py
```

## Performance Considerations

### 1. Connection Reuse
```python
self.session = requests.Session()
```
- Reuses TCP connections
- Faster for multiple requests to same host

### 2. Timeout Configuration
```python
self.timeout = 10
```
- Prevents hanging on slow servers
- Configurable per scan

### 3. Parallel Scanning
```python
with ThreadPoolExecutor(max_workers=5) as executor:
    # Concurrent requests
```

**Benefits**:
- Faster scanning of multiple parameters
- Configurable concurrency

**Considerations**:
- May trigger rate limiting
- Requires thread-safe code
- More resource intensive

### 4. Memory Management
- **Streaming**: Not used (responses are small)
- **Garbage collection**: Automatic
- **Result storage**: In-memory list (fine for typical scans)

### Performance Metrics

**Typical scan performance**:
- Single parameter, single context: 1-3 seconds
- 10 parameters, 4 contexts, 5 payloads each: 200 requests
- Sequential: ~200 seconds (1s per request)
- Parallel (10 workers): ~20 seconds

## Security Considerations

### 1. Ethical Use
- Tool is for **authorized testing only**
- Includes legal disclaimer
- No exploitation, only detection

### 2. Payload Safety
- Uses `alert()` for proof of concept
- No destructive payloads
- No cookie stealing or session hijacking

### 3. Rate Limiting
- May need to add delay between requests
- Respect target server resources
- Consider adding `--delay` option

### 4. Authentication
- Supports cookies and headers
- No password storage
- Users provide session tokens

### 5. Error Handling
```python
try:
    response = self.session.get(url)
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
```
- Graceful failure
- No sensitive info in errors
- Continues scanning on individual failures

## Future Enhancements

### Priority 1: Context Auto-Detection
```python
def auto_detect_context(self, url, param, probe_payload):
    # Send probe
    # Analyze response structure
    # Return detected context
```

### Priority 2: Advanced Encoding Detection
- JavaScript unicode escaping
- JSON escaping
- Double encoding
- Recursive encoding

### Priority 3: Filter Bypass
```python
class FilterBypass:
    def obfuscate_payload(self, payload):
        # Case variation
        # Comment insertion
        # Character encoding
        # Tag breaking
```

### Priority 4: Headless Browser Validation
```python
from selenium import webdriver

def validate_xss(self, url, payload):
    driver = webdriver.Chrome()
    driver.get(url)
    # Check if alert actually fires
```

### Priority 5: Machine Learning Context Detection
```python
import tensorflow as tf

class ContextClassifier:
    def predict_context(self, html_snippet):
        # Train model on labeled samples
        # Predict context from HTML structure
```

## Testing Strategy

### Unit Tests
- Test each component in isolation
- Mock HTTP requests
- Verify payload generation
- Check detection logic

### Integration Tests
- Test complete workflow
- Use test servers
- Verify report generation

### Regression Tests
- Maintain test suite
- Run on each code change
- Catch breaking changes

## Conclusion

This XSS scanner demonstrates:
- ✅ Clean, modular architecture
- ✅ Context-aware payload generation
- ✅ Robust reflection detection
- ✅ Professional reporting
- ✅ Extensible design
- ✅ Security-conscious implementation

The design prioritizes **clarity, maintainability, and correctness** over complexity, making it easy to understand, test, and extend.
