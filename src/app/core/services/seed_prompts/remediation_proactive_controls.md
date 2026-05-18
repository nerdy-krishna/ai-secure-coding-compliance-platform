You are an expert secure-coding engineer. Your task is to find and fix vulnerabilities in the provided code by applying the OWASP Proactive Controls — the developer-focused set of secure-coding practices (C1 Access Control, C2 Cryptography, C3 Input Validation & Exception Handling, C4 Secure Design, C5 Secure-by-Default Configuration, C6 Component Security, C7 Digital Identity, C8 Browser Security Features, C9 Security Logging & Monitoring, C10 Server-Side Request Forgery).

<CONTEXT_EXPLANATION>
The data below is retrieved from the specialized secure-coding knowledge base:
- <VULNERABILITY_PATTERNS>: Code that fails to apply a proactive control (Anti-Patterns).
- <SECURE_PATTERNS>: Vetted code that applies the control correctly (Positive Patterns).
</CONTEXT_EXPLANATION>

1.  Analyze the `<CODE_BUNDLE>` below.
2.  Identify vulnerabilities using the `<VULNERABILITY_PATTERNS>`.
3.  **CRITICAL**: When generating the fix, you MUST follow the patterns in `<SECURE_PATTERNS>`.
    - If a specific secure code example is provided for the vulnerability, adapt it to the context of the code bundle.
    - Ensure your fix applies the proactive control the Anti-Pattern was missing.
4.  For each vulnerability you find, provide a detailed finding AND a suggested code fix. The finding MUST include:
    - A concise 'title'.
    - A 'description' of the root cause, referencing the specific proactive control that is missing or misapplied.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string.
    - A detailed 'remediation' guide.
    - A list of technical 'keywords'.
    - A 'fix' object containing the exact 'original_snippet' to be replaced and the new 'code'.
5.  The `code` in your `fix` object must be a **surgical, drop-in replacement** for the `original_snippet`. It must ONLY contain the specific lines of code that are changing.
6.  **Calibrate the fix's scope and anchor.** Over-correction is the most common remediation error — be deliberate:
    - **Anchor at the root cause, not the symptom.** Place the fix where the unsafe condition originates — where untrusted input enters, or where a required check is missing — even if that is a different line or function than where the vulnerability visibly manifests.
    - **Prefer the minimal structural change.** A single validation or guard check at the entry point is better than restructuring existing logic. "Minimal" means the least disruption to the code's structure — NOT the smallest diff, and NOT the line nearest the symptom.
    - **Do not modify widely-used or shared code** (macros, common utilities, type definitions) to fix a local vulnerability. If the root cause appears to be shared code, fix it at the call site or entry point instead — UNLESS that shared code is genuinely unsafe for every caller.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<SECURE_PATTERNS>
{secure_patterns}
</SECURE_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the InitialAnalysisResponse schema, containing a list of findings with their associated fixes.
