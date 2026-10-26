# Manual Security Testing Report

## 1. Project Information

**Project:** DevSecOps SAST/DAST Lab
**Application:** Intentionally Vulnerable Flask Web Application
**Testing Environment:** Kali Linux and Docker
**Testing Type:** Manual Web Application Security Testing

## 2. Objective

The objective of this testing was to manually examine two potentially vulnerable behaviors in the locally hosted Flask application before conducting automated security scans.

The tests focused on unsafe HTML output handling and missing access control.

## 3. Test Case 1: Reflected HTML Injection

**Endpoint:** `/search`
**HTTP Method:** GET
**Parameter:** `q`

### Test Procedure

The following URL was opened in the browser:

`http://127.0.0.1:5000/search?q=%3Ci%3Ehello%3C%2Fi%3E`

The encoded input represents the HTML markup `<i>hello</i>`.

### Observed Result

The application rendered the word "hello" in italics.

The server also returned the supplied HTML markup without escaping it.

### Security Impact

This behavior demonstrates unsafe HTML output handling and indicates potential reflected cross-site scripting (XSS).

Further testing is required to confirm whether attacker-controlled JavaScript can execute.

### Evidence

Screenshot: `screenshots/search-html-reflection.png`

### Recommended Remediation

Use context-appropriate output encoding. When rendering user input with Flask and Jinja templates, keep automatic HTML escaping enabled and avoid marking untrusted input as safe.

## 4. Test Case 2: Missing Access Control

**Endpoint:** `/user/1`
**HTTP Method:** GET

### Test Procedure

The following command was executed in the Kali Linux terminal without logging in:

`curl -i http://127.0.0.1:5000/user/1`

### Observed Result

The application returned the following user record:

`(1, 'admin')`

The record was accessible without authentication.

### Security Impact

The endpoint does not enforce authentication or authorization before returning the user record.

In a real application, similar behavior could expose information to unauthorized users.

### Evidence

Screenshot: `screenshots/missing-access-control.png`

### Recommended Remediation

Require authentication where appropriate and implement server-side authorization checks to ensure that users can access only the records they are permitted to view.

## 5. Summary

Two behaviors were examined manually:

1. The search endpoint returned user-controlled HTML without escaping it.
2. The user-profile endpoint returned a record without requiring authentication.

These observations provide an initial baseline for the project's security assessment.

Automated SAST and DAST scans will be performed in subsequent phases to identify additional issues and evaluate the application's security.

## 6. Testing Limitations

This report records observations from a local demonstration application. It does not represent a complete security assessment.

The reflected HTML behavior has not, by itself, established JavaScript execution. The access-control finding is limited to the demonstrated user-profile endpoint.

All testing was performed against the locally hosted lab application.
