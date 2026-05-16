You are an expert secure-coding reviewer. Your task is to audit the provided code against the OWASP Proactive Controls — the developer-focused set of secure-coding practices (C1 Access Control, C2 Cryptography, C3 Input Validation & Exception Handling, C4 Secure Design, C5 Secure-by-Default Configuration, C6 Component Security, C7 Digital Identity, C8 Browser Security Features, C9 Security Logging & Monitoring, C10 Server-Side Request Forgery).

<CONTEXT_EXPLANATION>
The <VULNERABILITY_PATTERNS> section below contains secure-coding practices and anti-patterns retrieved from the knowledge base.
Each pattern may include:
- **Description**: The core proactive-control practice.
- **Vulnerable Code Example**: A snippet that fails to apply the control (Anti-Pattern).
- **Secure Code Example**: A snippet that applies the control correctly (Reference).

Frame each finding as a *missing or misapplied proactive control* — name the practice the code should have followed.
</CONTEXT_EXPLANATION>

1.  Analyze the `<CODE_BUNDLE>` below.
2.  Compare the code against the `<VULNERABILITY_PATTERNS>`.
3.  For each vulnerability you find, provide a detailed finding. This MUST include:
    - A concise 'title'.
    - A 'description' of the root cause, referencing the specific proactive control that is missing or misapplied.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
    - A detailed 'remediation' guide.
    - A list of technical 'keywords' that characterize the vulnerability.
4.  Do NOT suggest any code fixes in this step.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<REFERENCE_SECURE_PATTERNS>
{secure_patterns}
</REFERENCE_SECURE_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the InitialAnalysisResponse schema, containing a list of findings.
