// SCCAP eval mock provider — sandboxed, deterministic, free.
//
// Sandbox contract (threat-model G7) — see evals/README.md "G7" section
// for the exact forbidden-token list. The CI workflow at
// .github/workflows/evals.yml greps this source for those tokens and
// fails the build if any appear; the literal tokens are intentionally
// not duplicated in this comment to avoid false-positive matches in
// the grep itself. Practically: this provider must do no env reads,
// no network, no shell exec, and no disk writes — only deterministic
// pattern-matching on its inputs.
//
// Behaviour:
//   Pattern-matches `context.vars.code_bundle` / `context.vars.user_question`
//   to produce sensible canned responses shaped like the real Pydantic AI
//   structured output:
//     - Analyzer prompts -> `InitialAnalysisResponse` shape
//       ({ findings: [{ title, description, severity, confidence, ... }] })
//     - Chat prompts     -> `ChatResponse` shape
//       ({ response: "..." })

"use strict";

function classifyCode(code) {
  const c = (code || "").toLowerCase();
  // Keep these checks intentionally simple — the goal is deterministic
  // signal for golden-output tests, not a real classifier.
  if (/cursor\.execute\(\s*f["'`]/.test(c) || /select.*\{.*\}/i.test(code || "")) {
    return "sql_injection";
  }
  if (/\|\s*safe\b/.test(c) || /innerhtml\s*=/.test(c)) {
    return "xss";
  }
  if (/@app\.(get|post|put|delete)\(/.test(c) && !/depends\(/i.test(c)) {
    return "auth_bypass";
  }
  return "clean";
}

function findingFor(kind) {
  switch (kind) {
    case "sql_injection":
      return [
        {
          title: "SQL Injection via f-string interpolation",
          description:
            "User-controlled value is concatenated into a SQL statement via f-string; an attacker can inject arbitrary SQL.",
          severity: "Critical",
          confidence: "High",
          line_number: 1,
          vulnerable_snippet:
            'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          remediation:
            "Use parameterised queries with the DB driver's `?` / `%s` placeholders.",
          keywords: ["sql", "injection", "f-string", "cursor.execute"],
        },
      ];
    case "xss":
      return [
        {
          title: "Cross-Site Scripting (XSS) via unsanitised template render",
          description:
            "User input is rendered with the `safe` filter (or assigned to innerHTML), bypassing escaping.",
          severity: "High",
          confidence: "High",
          line_number: 1,
          vulnerable_snippet: "element.innerHTML = userInput;",
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          remediation:
            "Remove the `safe` filter or escape the value with `bleach.clean` / `html.escape` before rendering.",
          keywords: ["xss", "template", "safe-filter", "innerHTML"],
        },
      ];
    case "auth_bypass":
      return [
        {
          title: "Missing authentication / authorization on endpoint",
          description:
            "Route handler does not call `Depends(current_active_user)` or an equivalent dependency, so the endpoint is reachable without an authenticated session.",
          severity: "High",
          confidence: "High",
          line_number: 1,
          vulnerable_snippet: '@app.get("/users/{user_id}")',
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          remediation:
            "Add `user = Depends(current_active_user)` to the route signature, or `Depends(current_superuser)` for admin-only paths.",
          keywords: ["authorization", "fastapi", "depends", "missing-auth"],
        },
      ];
    case "clean":
    default:
      return [];
  }
}

function chatResponseFor(question) {
  const q = (question || "").toLowerCase();
  if (q.includes("injection") || q.includes("sqli") || q.includes("a03")) {
    return "OWASP A03:2021 — Injection — covers SQL, NoSQL, OS-command, and template injection. Mitigate by treating all user input as untrusted: use parameterised queries (e.g. `cursor.execute(sql, params)`), strict input validation against an allow-list, and least-privilege DB accounts.";
  }
  if (q.includes("dismiss") || q.includes("false positive") || q.includes("triage")) {
    return "Before dismissing a finding, capture the rationale (why it's not exploitable in this context), the reviewer's identity, and a re-evaluation date. Dismissals without compensating controls are a common audit gap.";
  }
  if (q.includes("source") || q.includes("cite") || q.includes("reference")) {
    return "According to the OWASP ASVS v5 (Verification 5.1.2) and the OWASP Cheatsheet on Input Validation, all server-side validation MUST occur on a trusted system and MUST use an allow-list approach for structured data.";
  }
  return "I don't have specific context on that question. As a general principle, refer to the OWASP Top 10 and ASVS for prioritised guidance, and prefer parameterised / allow-listed implementations over ad-hoc sanitisation.";
}

// Promptfoo's custom-provider loader expects a constructor — `new
// require(file)(...)` — so the export is a class, not a plain object.
class SccapMockProvider {
  id() {
    return "sccap-mock";
  }
  async callApi(_prompt, context) {
    const vars = (context && context.vars) || {};
    if (typeof vars.user_question === "string") {
      const reply = chatResponseFor(vars.user_question);
      return {
        output: JSON.stringify({ response: reply }),
        // Promptfoo wants tokenUsage; report zeros (mock is free).
        tokenUsage: { total: 0, prompt: 0, completion: 0 },
      };
    }
    const kind = classifyCode(vars.code_bundle);
    const findings = findingFor(kind);
    return {
      output: JSON.stringify({ findings }),
      tokenUsage: { total: 0, prompt: 0, completion: 0 },
    };
  }
}

module.exports = SccapMockProvider;
