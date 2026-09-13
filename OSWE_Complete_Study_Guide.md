# OSWE — Offensive Security Web Expert (AWAE)

**Author:** DarcHacker

**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)

---

## Table of Contents

| # | Module | Key Topics |
|---|---|---|
| 01 | Introduction | About the AWAE Course, Lab Setup, Reporting |
| 02 | Tools & Methodologies | Burp Suite, Python, Source Code Recovery, Debugging |
| 03 | ATutor Authentication Bypass and RCE | Blind SQLi, Authentication Bypass, File Upload RCE |
| 04 | ATutor LMS Type Juggling Vulnerability | PHP Loose Comparisons, Magic Hashes, Account Hijacking |
| 05 | ManageEngine Applications Manager SQL Injection RCE | Servlet Analysis, Blind SQLi, PostgreSQL UDF & Large Objects |
| 06 | Bassmaster NodeJS Arbitrary JavaScript Injection | Node.js, `eval()` Injection, Reverse Shell |
| 07 | DotNetNuke Cookie Deserialization RCE | .NET Serialization, XmlSerializer, ObjectDataProvider Gadget |
| 08 | ERPNext Authentication Bypass and SSTI | MVC, SQLi, Server-Side Template Injection, Jinja2 |
| 09 | openCRX Authentication Bypass and RCE | Predictable PRNG, XXE, HSQLDB JRT, Web Shell |
| 10 | openITCOCKPIT XSS and OS Command Injection | Blackbox Testing, DOM XSS, WebSocket, Command Injection |
| 11 | Concord Authentication Bypass to RCE | CORS, CSRF, Insecure Defaults, Groovy Scripting |
| 12 | Server Side Request Forgery | Microservices, API Discovery, Blind SSRF, Headless Chrome Exploitation |
| 13 | Guacamole Lite Prototype Pollution | JavaScript Prototypes, Prototype Pollution, EJS & Handlebars RCE |
| 14 | Conclusion | Course Summary, Extra Miles, Further Practice |

---

## 01 Introduction

### About the AWAE Course

This course is designed to develop and expand your exploitation skills in web application penetration testing and exploitation research. It is not an entry-level course. We will dive into, read, understand, and write code in several languages, including JavaScript, PHP, Java, and C#.

The goal is to expose you to a general and repeatable approach to web application vulnerability discovery and exploitation, focusing on chained vulnerabilities that lead to a compromise of the underlying host operating system.

### Our Approach

The AWAE labs are less diverse and contain a few test case scenarios that the course focuses on. A set of dedicated virtual machines hosting these scenarios will be available to each student. Explanations are sometimes intentionally vague to challenge you and ensure the concept behind the module is clear.

We suggest you:
1.  Read the book module for general familiarity.
2.  Watch the accompanying video for that module.
3.  Recreate the exercise in the lab.
4.  Perform the "Extra Mile" exercises.
5.  Document your findings.

A heavy focus of the course is on whitebox application security research, so that you can create exploits for vulnerabilities in widely deployed appliances and technologies.

### Reporting

Students opting for the OSWE certification must submit an exam report clearly demonstrating how they successfully achieved the certification exam objectives. This final report must be sent back to the Certification Board in PDF format no more than 24 hours after the completion of the certification exam.

---

## 02 Tools & Methodologies

### Web Traffic Inspection

When dealing with an unknown web application, we should always begin with traffic inspection. A web application proxy is an indispensable tool for capturing client requests and server responses and manipulating a chosen request in arbitrary ways. We will primarily use Burp Suite.

**Burp Suite Proxy:**
- The embedded Chromium browser is preconfigured to proxy traffic through Burp.
- Use the `Intercept` tab to inspect and forward/drop requests.
- The `HTTP history` tab lists the entire session history.
- Set a `Scope` to filter out unwanted traffic (e.g., third-party statistics collectors).

**Burp Suite Repeater and Comparer:**
- **Repeater:** Used to make arbitrary and very precise changes to a captured request and resend it. This is useful for determining how granular changes affect the response.
- **Comparer:** Used to perform a word or byte-level comparison between different data. This is useful for highlighting subtle differences between two HTTP responses.

**Burp Suite Decoder:**
- A versatile tool for encoding, decoding, and hashing data. It can be used to decode Base64-encoded values found in requests or responses.

### Interacting with Web Listeners using Python

We will be creating complex web application exploits in Python. The `requests` library is used to interact with web applications.

```python
import requests
from colorama import Fore, Back, Style

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def format_text(title,item):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    item = str(item)
    text = Style.BRIGHT + Fore.RED + title + Fore.RESET + section_break + item + section_break
    return text;

r = requests.get('https://manageengine:8443/',verify=False, proxies=proxies)
print(format_text('r.status_code is: ',r.status_code))
print(format_text('r.headers is: ',r.headers))
print(format_text('r.cookies is: ',r.cookies))
print(format_text('r.text is: ',r.text))
Source Code Recovery
For compiled applications, we need to recover the source code.

Managed .NET Code:

Use dnSpy to decompile .NET executables. It uses the ILSpy decompiler engine.

Decompilation: Drag the .exe or .dll file into dnSpy to view the source code.

Cross-References: Use the "Analyze" feature to find where a function is used or what it uses. This is invaluable for tracing code logic.

Modifying Assemblies: You can edit class attributes or even entire methods and save the modified assembly. This is useful for debugging.

Decompiling Java Classes:

Use JD-GUI to decompile Java bytecode (.class files) and Java Archives (.jar files).

Open a JAR file in JD-GUI to view the decompiled Java source code.

Source Code Analysis Methodology
Analysis of source code is arguably the hardest technique to master. We need to be mindful of sources (where data enters) and sinks (where data is used or operated on).

An Approach to Analysis:

Top-Down: Identify sources first, then trace the application flow to the sinks.

Bottom-Up: Identify sinks first, then trace the application flow back to a source.

Using an IDE:

Visual Studio Code is a powerful tool for source code analysis. It supports advanced code search and debugging.

Use grep and regular expressions to find interesting patterns.

Use "Find All References" to locate where a function or method is called.

Common HTTP Routing Patterns:

File System Routing: Maps URL to a file on the server's filesystem (e.g., Apache, Nginx).

Servlet Mappings: Java applications use web.xml to map URLs to servlets.

Routing by Annotation: Frameworks like Spring MVC or Flask use annotations or decorators in the source code to define routes.

Debugging
Debugging reveals the inner workings of an application at runtime. We will use Visual Studio Code to debug Java applications.

Remote Debugging:

Allows debugging a process running on a different system.

For Java, start the JAR with the -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=9898 flag.

In VS Code, create a launch.json file with an "Attach to Remote Program" configuration.

03 ATutor Authentication Bypass and RCE
ATutor is a web-based Learning Management System. This module covers the in-depth analysis and exploitation of multiple vulnerabilities in ATutor 2.2.1.

Initial Vulnerability Discovery
By enabling database logging and PHP error display, we can analyze the application's behavior. We find a publicly accessible page, index_public.php, which passes user-controlled input from the q GET parameter to a searchFriends function.

Vulnerable Code:

php
// index_public.php
if (isset($_GET['q'])){
    $query = $addslashes($_GET['q']);
    //retrieve a list of friends by the search
    $search_result = searchFriends($query);
}
The $addslashes function is not the native PHP function. In this environment, it resolves to trim, providing no sanitization.

The searchFriends function builds a SQL query by concatenating the user-controlled $query variable.

php
// friends.inc.php
$sql = 'SELECT * FROM '.TABLE_PREFIX.'members M WHERE ';
// ...
$sql = $sql . $query;
$rows_members = queryDB($sql, array());
The queryDB function is designed to use parameterized queries but is misused here. The $query is passed as the first argument (the query string itself), not as a parameter array, so it is not sanitized. This results in a SQL injection vulnerability.

Data Exfiltration
Since the results of the query are not directly displayed, this is a blind SQL injection. We can use boolean-based inference to extract data. We craft payloads to ask TRUE/FALSE questions to the database.

True Query: test')/**/or/**/(select/**/1)=1%23

False Query: test')/**/or/**/(select/**/1)=0%23

We can use the Content-Length header of the HTTP response to differentiate between TRUE and FALSE results. A Content-Length > 20 indicates a TRUE response.

We can then use a script to extract the MySQL version and other data by iterating through characters using substring and ascii functions.

Subverting the ATutor Authentication
The authentication logic in login_functions.inc.php constructs the following query:

sql
SELECT ... FROM %smembers WHERE (login='%s' OR email='%s') AND SHA1(CONCAT(password, '%s'))='%s'
The parameters are passed correctly, but the password check uses SHA1(CONCAT(password, $SESSION['token'])). The token is user-controlled via a POST parameter. By using the SQL injection to retrieve the teacher user's password hash, we can calculate the correct value for the form_password_hidden parameter and log in as the teacher.

Bypassing File Upload Restrictions
As a teacher, we can upload files. The application only accepts ZIP files. The contents are inspected for an imsmanifest.xml file. A malformed XML file will cause the script to die after extraction, leaving the extracted files on the filesystem. We can create a ZIP file with a directory traversal payload to escape the /var/content jail and write a file to a web-accessible directory like /var/www/html/ATutor/mods/. The extension filter is bypassed by using .phtml instead of .php.

Attack Chain:

Use SQL injection to disclose the teacher's password hash.

Log in with the disclosed hash.

Upload a ZIP that contains a PHP file (.phtml) and uses directory traversal to write it into the web root.

Gain remote code execution.

04 ATutor LMS Type Juggling Vulnerability
This module covers a PHP Type Juggling vulnerability in ATutor.

PHP Loose and Strict Comparisons
PHP's loose comparison operator (==) performs implicit type conversions. This can lead to unexpected behavior. The confirm.php script uses a loose comparison to validate a password reset token.

php
// confirm.php
if ($code == $m) {
    // UPDATE EMAIL
}
$code is a 10-character MD5 hash substring: substr(md5($e . $row['creation_date'] . $id), 0, 10).

$m is user-controlled.

$e (new email) is user-controlled.

$id (user ID) is user-controlled.

$row['creation_date'] is from the database.

Attacking the Loose Comparison
We can use a "Magic Hash" to bypass this check. A Magic Hash is a string that starts with 0e followed by only digits. In PHP, when such a string is used in a numeric context, it is interpreted as 0.

If we can find an email address ($e) such that the first 10 characters of the MD5 hash of $e . $creation_date . $id match the 0e[0-9]+ pattern, we can set $m=0 to satisfy the comparison.

We can write a script to brute-force the email address to find a Magic Hash. For example, atx@offsec.local might produce a hash like 0e77973356.

Exploitation
Once a valid "Magic Email" is found, we can:

Send a request to confirm.php with the magic email (e), the user ID (id), and m=0.

This updates the target user's email to our controlled email address.

Use the "Forgot Password" feature to send a password reset link to the new email.

Reset the password and gain access to the account.

05 ManageEngine Applications Manager SQL Injection RCE
This module covers a SQL Injection vulnerability in the AMUserResourcesSyncServlet in ManageEngine Applications Manager.

Vulnerability Discovery
By decompiling the AdventNetAppManagerWebClient.jar file, we can analyze the source code. The doGet method in AMUserResourcesSyncServlet retrieves user-controlled parameters, including userId. This parameter is concatenated into a SQL query in the fetchUserResourcesofMASForUserid function without sanitization.

java
String qry = "select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=" + userid + " and RESOURCEID >" + stRange + " and RESOURCEID <" + endRange;
This is a SQL injection vulnerability.

Exploitation
The application uses PostgreSQL, which allows stacked queries. However, the results of the query are not returned, making it a blind SQL injection. We can use time-based injection with pg_sleep() to confirm and exploit the vulnerability.

The COPY function in PostgreSQL allows reading from and writing to the file system. We can use COPY (SELECT ...) TO 'filename' to write a file. To bypass restrictions on single quotes, we can use PostgreSQL's dollar-quoted string constants ($$string$$).

Reverse Shell via UDF:

Compile a custom PostgreSQL extension (UDF) that executes a command or opens a reverse shell.

Use the SQL injection to write the DLL to the file system. We can use Large Objects (lo_import, lo_export) to write binary data.

Create a UDF pointing to the DLL: CREATE OR REPLACE FUNCTION ... AS 'C:\path\to\evil.dll', 'connect_back' LANGUAGE C STRICT;

Trigger the UDF to execute the reverse shell.

06 Bassmaster NodeJS Arbitrary JavaScript Injection
Bassmaster is a batch processing plugin for the hapi framework on Node.js.

Vulnerability Discovery
A grep search for eval() reveals a dangerous call in lib/batch.js. The parts array, which is populated from user-controlled URL paths, is used to construct a string that is passed to eval().

javascript
// lib/batch.js
eval('value = ref.' + parts[i].value + ';');
This allows for arbitrary JavaScript code injection.

Triggering the Vulnerability
A POST request to the /batch endpoint with a specially crafted JSON payload can trigger the vulnerability. The path parameter in the JSON object is vulnerable.

Payload:

json
{"requests": [{"method": "get", "path": "/item/$1.id;require('util').log('CODE_EXECUTION');"}]}
Obtaining a Reverse Shell
A reverse shell can be obtained by injecting a Node.js reverse shell payload. Character restrictions (forward slashes) are bypassed by using hex-encoded characters (e.g., \x2f for /).

07 DotNetNuke Cookie Deserialization RCE
This module covers a deserialization vulnerability in the DotNetNuke (DNN) platform via the DNNPersonalization cookie.

Serialization Basics
.NET's XmlSerializer can only serialize public properties and fields of an object. It cannot serialize methods.

DotNetNuke Vulnerability Analysis
The LoadProfile function in DotNetNuke.dll reads the DNNPersonalization cookie and passes it to a DeserializeHashTableXml function, which eventually deserializes the data using XmlSerializer without proper type checking. This can be triggered by visiting a non-existent page.

Exploitation with ObjectDataProvider
We can't directly serialize a method call. Instead, we use the ObjectDataProvider gadget. This class has a MethodName property that, when set, triggers the invocation of that method on the wrapped object (ObjectInstance).

We wrap a FileSystemUtils object and call its PullFile method, which can download a file from a URL to the server.

To make this object serializable by XmlSerializer, we wrap it in an ExpandedWrapper object. This allows us to define the types of the wrapped objects, satisfying the serializer.

Attack Chain:

Create a serialized payload using ExpandedWrapper<FileSystemUtils, ObjectDataProvider>.

Set MethodName to PullFile and provide the URL of an ASPX web shell and the destination path on the server.

Place the serialized XML in the DNNPersonalization cookie and send a request to a non-existent page.

The server downloads the web shell, granting RCE.

08 ERPNext Authentication Bypass and Server Side Template Injection
This module covers a SQL injection and a Server-Side Template Injection (SSTI) vulnerability in ERPNext, built on the Frappe framework.

Authentication Bypass Discovery
The web_search function in global_search.py is a guest-whitelisted function. It constructs an SQL query where the scope parameter is not properly escaped.

python
scope_condition = '`route` like "{}%" AND '.format(scope) if scope else ''
This allows for a SQL injection. We can use a UNION-based injection to extract data from the database.

Exploitation:

Use SQL injection to extract the reset_password_key for the Administrator user from the tabUser table.

Use the key to visit the password reset page (/update-password?key=...) and set a new password for the Administrator.

SSTI Vulnerability Discovery & Exploitation
With admin access, we can create Email Templates. Frappe uses the Jinja templating engine to render these templates. The render_template function attempts to block SSTI by filtering out the string .__.

Filter Bypass:
We can bypass this filter by using Jinja's attr filter. For example, instead of ''.__class__, we can use ''|attr('__class__').

RCE:
Once the filter is bypassed, we can traverse the Python object hierarchy to find a class that allows command execution, such as subprocess.Popen.

Get the object class: ''|attr('__class__')|attr('__mro__') -> access index 1.

List subclasses: ...|attr('__subclasses__')().

Find the index of subprocess.Popen in the list.

Execute a command: ...|attr('__subclasses__')()[420](['/usr/bin/touch','/tmp/pwned']).

09 openCRX Authentication Bypass and Remote Code Execution
This module covers vulnerabilities in the openCRX Java web application.

Password Reset Vulnerability
The getRandomBase62 function in org.opencrx.kernel.utils.Util.java uses java.util.Random seeded with System.currentTimeMillis() to generate password reset tokens. This is not cryptographically secure and is predictable.

Exploitation:

Trigger a password reset for a known user (e.g., guest) and record the start and end timestamps in milliseconds.

Write a Java program that iterates through the possible seed values in that time range, generating the corresponding tokens.

Use a script to spray the tokens against the PasswordResetConfirm.jsp endpoint until the password is successfully reset.

XML External Entity (XXE) Vulnerability
The openCRX API accepts XML input. By injecting a malicious DTD with an external entity that references a local file (e.g., file:///etc/passwd), we can read files on the server. The contents of the file are reflected in the error message.

We can read the tomcat-users.xml file to get credentials, but they don't work for the Tomcat Manager. Instead, we read a script file (dbmanager.sh) to get credentials for the HSQLDB database.

HSQLDB and Remote Code Execution
We connect to the internal HSQLDB instance using the discovered credentials. HSQLDB allows the creation of Java Language Routines (JRTs), which can call static methods of Java classes.

We can create a procedure that calls com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename. This method writes a byte array to a file.

Attack Chain:

Connect to the HSQLDB instance.

Create a procedure to call writeBytesToFilename.

Convert a JSP web shell to a byte array (e.g., hex).

Call the procedure to write the JSP web shell to a directory within the openCRX web application.

Access the JSP web shell to execute commands.

10 openITCOCKPIT XSS and OS Command Injection - Blackbox
This module covers a blackbox assessment of openITCOCKPIT, chaining a DOM-based XSS with a WebSocket command injection.

XSS Hunting
By exploring the application's JavaScript libraries (e.g., lodash), we find a DOM-based XSS vulnerability in a performance testing page. The build query parameter is used unsanitized to construct a script source URL.

Payload: /lodash/perf/index.html?build=... can be used to inject and execute JavaScript.

Advanced XSS Exploitation
We use the XSS to target an authenticated user. We create a payload that scrapes the user's home page, extracts all links, fetches the content of each link, and sends it back to a server we control. This allows us to discover API endpoints and WebSocket details.

RCE Hunting
The scraped content reveals a WebSocket endpoint (sudo_server) and an API key (akey). We build a custom Python WebSocket client to interact with this endpoint. We discover that it allows running a limited set of commands, including ./check_http.

By fuzzing the arguments of check_http, we find a command injection vulnerability in its -k argument, which allows us to execute arbitrary commands via the su command.

Payload: ./check_http -I ... -p ... -k 'test -c 'echo 'hacked''

11 Concord Authentication Bypass to RCE
This module covers multiple authentication bypass vulnerabilities in the Concord workflow server.

CORS and CSRF
The Concord API has permissive CORS headers, reflecting the Origin header and allowing credentials (Access-Control-Allow-Credentials: true). This allows a malicious website to send requests on behalf of an authenticated user and read the responses.

Exploitation:

We find an API endpoint (/api/v1/process) that accepts a multipart/form-data POST request. This type of request does not require a preflight OPTIONS request, so it is not subject to the stricter CORS policy on OPTIONS requests.

We craft a concord.yml file that defines a flow to execute a Groovy reverse shell.

The malicious website sends a POST request to the /api/v1/process endpoint, uploading the concord.yml file as a form part.

This starts a process on the server, executing our reverse shell.

Insecure Defaults
The source code contains database migration files (v0.69.0.xml) with a default API key for the concordAgent user.

Exploitation:

Extract the plaintext API key from the migration file.

Use the API key to authenticate to the Concord API.

Use the authenticated API to start a process with a concord.yml file to execute a reverse shell.

12 Server Side Request Forgery
This module presents a blackbox methodology for testing microservices, focusing on a blind SSRF vulnerability in Directus.

SSRF Discovery
We discover an endpoint /files/import that accepts a url parameter. The application sends a GET request to the provided URL. This is a classic SSRF vulnerability.

Exploiting Blind SSRF
Although we can't see the response of the SSRF, we can use it to:

Port Scan: By sending requests to different ports on localhost or other internal hosts, we can infer if a port is open based on the HTTP response code and error messages (e.g., ECONNREFUSED vs. a timeout or a 403 error).

Subnet Scan: By scanning for IPs that respond quickly, we can identify live hosts on the internal network.

Host Enumeration: By scanning common ports on the discovered live hosts, we can map out the internal services (e.g., Kong API Gateway on 8000, Directus on 8055).

Exploiting Headless Chrome
We discover a /render service that uses Headless Chrome to generate a PDF from a URL. We can call this service via the SSRF vulnerability. This allows us to execute arbitrary JavaScript in the context of the Headless Chrome browser.

Exfiltration and RCE:

Use JavaScript to make requests to internal services and exfiltrate the responses back to our server.

Steal API keys from the Kong Admin API.

Use the Kong Admin API to enable the pre-function plugin, which allows executing Lua code. We can inject a Lua reverse shell payload to get RCE on the Kong Gateway container.

13 Guacamole Lite Prototype Pollution
This module demonstrates how to exploit a prototype pollution vulnerability in the guacamole-lite library to achieve RCE by exploiting different templating engines.

JavaScript Prototype
In JavaScript, almost everything is an object. Each object has a link to another object called its prototype. This forms a prototype chain. If a property is not found on an object, JavaScript will traverse the prototype chain to find it. The __proto__ property is a link to the prototype of an object.

Prototype Pollution
Prototype pollution occurs when an attacker can inject properties into the Object.prototype. This is often found in merge or extend functions that recursively merge user-controlled objects without sanitizing keys.

Vulnerable Library: guacamole-lite@0.6.3 uses deep-extend@0.4.2, which is vulnerable.

Payload:

json
{
  "connection": {
    "settings": {
      "__proto__": {
        "polluted": "true"
      }
    }
  }
}
Exploitation via EJS
The EJS templating engine has an outputFunctionName option that is used to build the compiled template function.

Vulnerable Code: 'var ' + opts.outputFunctionName + ' = __append;'

Payload: By polluting outputFunctionName, we can inject arbitrary JavaScript that will be executed when the template is compiled.

json
{
  "__proto__": {
    "outputFunctionName": "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()) ; y"
  }
}
Exploitation via Handlebars
Handlebars compiles templates into an Abstract Syntax Tree (AST) and then into JavaScript code. We can trick Handlebars into using our own malicious AST by polluting the Object.prototype with a type: "Program" and a body array.

Payload: The body array contains a MustacheStatement with a NumberLiteral parameter. The value of this literal is our malicious JavaScript code, which is injected into the compiled template function.

json
{
  "__proto__": {
    "type": "Program",
    "body":[{
      "type": "MustacheStatement",
      "path":0,
      "loc": 0,
      "params":[{
        "type": "NumberLiteral",
        "value": "console.log(process.mainModule.require('child_process').execSync('whoami').toString())"
      }]
    }]
  }
}
14 Conclusion
This course has explored a wide range of web application vulnerabilities and exploitation techniques, including:

Authentication bypass via SQL injection, type juggling, and predictable tokens.

Remote code execution through insecure file uploads, code injection, deserialization, and SSTI.

Chaining vulnerabilities to escalate from unauthenticated access to remote shells.

We have covered whitebox, blackbox, and greybox methodologies, demonstrating the importance of source code analysis, debugging, and creative problem-solving.

The journey of a web application security researcher is one of continuous learning. The methodologies provided are suggestions; we encourage you to develop your own and always remember to Try Harder.

OSWE | Offensive Security | “The goal is not to get Domain Admin. The goal is to understand WHY you got Domain Admin.”

By DarcHacker.

LinkedIn: Mostafa Ibrahim

text

This Markdown file is a complete, professional, and self-contained guide based on the provided course materials. It omits the specific exam details and company information as requested, adhering to your format and content guidelines.
