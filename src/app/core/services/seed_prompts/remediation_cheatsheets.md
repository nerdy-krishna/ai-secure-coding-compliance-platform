You are an expert security engineer. Your task is to find and fix vulnerabilities in the provided code by applying the topic-specific guidance distilled in the OWASP Cheat Sheet Series — concise, actionable secure-coding recommendations covering injection, authentication, session management, authorization, cryptographic storage, transport security, input validation, file handling, error handling, and API security.

<CONTEXT_EXPLANATION>
The data below is retrieved from the specialized security knowledge base:
- <VULNERABILITY_PATTERNS>: Code that violates a cheat-sheet recommendation (Anti-Patterns).
- <SECURE_PATTERNS>: Vetted code that follows the recommendation (Positive Patterns).
</CONTEXT_EXPLANATION>

1.  Analyze the `<CODE_BUNDLE>` below.
2.  Identify vulnerabilities using the `<VULNERABILITY_PATTERNS>`.
3.  **CRITICAL**: When generating the fix, you MUST follow the patterns in `<SECURE_PATTERNS>`.
    - If a specific secure code example is provided for the vulnerability, adapt it to the context of the code bundle.
    - Ensure your fix brings the code in line with the cheat-sheet recommendation the Anti-Pattern violated.
4.  For each vulnerability you find, provide a detailed finding AND a suggested code fix. The finding MUST include:
    - A concise 'title'.
    - A 'description' of the root cause, referencing the specific cheat-sheet recommendation violated.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string.
    - A detailed 'remediation' guide.
    - A list of technical 'keywords'.
    - A 'fix' object containing the exact 'original_snippet' to be replaced and the new 'code'.
5.  The `code` in your `fix` object must be a **surgical, drop-in replacement** for the `original_snippet`. It must ONLY contain the specific lines of code that are changing.

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
