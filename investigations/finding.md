## Challenge 1 (CH1) - Authentication Bypass

**Challenge ID:** CH1  
**Target URL:** http://127.0.0.1:8001  
**Finding Summary:** Authentication bypass vulnerability in login endpoint. The application accepts JSON requests with only a username field (no password), returning an "internal-access" token. This allows attackers to bypass authentication entirely.  
**Detection Method:** Custom Nuclei template that sends a POST request with only username in JSON body  
**Template File:** [ch1-auth-bypass.yaml](templates/ch1-auth-bypass.yaml)

### Vulnerability Details
- **Endpoint:** `/login` (POST)
- **Vulnerability Type:** Broken Authentication
- **Severity:** Critical
- **Root Cause:** Missing validation for required password field

---

## Challenge 2 (CH2) - Path Traversal

**Challenge ID:** CH2  
**Target URL:** http://127.0.0.1:8002  
**Finding Summary:** Path traversal vulnerability in file download endpoint. The application uses `os.path.normpath()` which can be bypassed with certain encoding techniques to access files outside the intended directory.  
**Detection Method:** Custom Nuclei template testing various path traversal payloads  
**Template File:** [ch2-path-traversal.yaml](templates/ch2-path-traversal.yaml)

### Vulnerability Details
- **Endpoint:** `/download?file=`
- **Vulnerability Type:** Local File Inclusion / Path Traversal
- **Severity:** High
- **Root Cause:** Insufficient path sanitization

---

## Challenge 3 (CH3) - IDOR in API

**Challenge ID:** CH3  
**Target URL:** http://127.0.0.1:8003  
**Finding Summary:** Insecure Direct Object Reference (IDOR) vulnerability in the orders API. The endpoint only checks for the presence of an Authorization header but doesn't validate ownership of the requested order. Any authenticated user can access any order by changing the order ID.  
**Detection Method:** Custom Nuclei template with arbitrary Authorization header accessing different order IDs  
**Template File:** [ch3-idor-api.yaml](templates/ch3-idor-api.yaml)

### Vulnerability Details
- **Endpoint:** `/api/orders/<oid>`
- **Vulnerability Type:** Broken Access Control / IDOR
- **Severity:** High
- **Root Cause:** Missing authorization check for resource ownership

---

## Challenge 4 (CH4) - SSRF Detection

**Challenge ID:** CH4  
**Target URL:** http://172.16.13.89:9004  
**Finding Summary:** Server-Side Request Forgery (SSRF) vulnerability detected through black-box testing. The application makes requests to user-supplied URLs, potentially allowing access to internal resources.  
**Detection Method:** Custom Nuclei template testing common SSRF parameters with internal URL payloads  
**Template File:** [ch4-ssrf-detection.yaml](templates/ch4-ssrf-detection.yaml)
### Vulnerability Details
- **Vulnerability Type:** Server-Side Request Forgery (SSRF)
- **Testing Model:** Black-box
- **Severity:** Critical
- **Potential Impact:** Access to internal services, cloud metadata, internal network scanning

---


