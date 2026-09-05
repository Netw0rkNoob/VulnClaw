# HackerOne Report Template and Scope Parsing Reference

This reference supports the `hackerone` Skill. It defines the target shape for
scope parsing and the report format for HackerOne submissions. Technical terms
and API identifiers remain in their original English form.

## 1. Scope parsing reference

### 1.1 Asset type (human label ↔ API enum)

| Human label | API enum | Directly supported by pentest-flow |
| --- | --- | --- |
| Domain / URL | `URL` | ✅ |
| Wildcard `*.x.com` | `WILDCARD` | ✅ |
| IP range / CIDR | `CIDR` | ⚠️ Confirm first; may be restricted |
| Source code | `SOURCE_CODE` | ❌ Manual handling |
| Android app | `GOOGLE_PLAY_APP_ID` / `OTHER_APK` | ❌ Requires a dedicated workflow |
| iOS app | `APPLE_STORE_APP_ID` / `TESTFLIGHT` / `OTHER_IPA` | ❌ Requires a dedicated workflow |
| Hardware | `HARDWARE` | ❌ Manual handling |
| AI model | `AI_MODEL` | ❌ Manual handling |
| Smart contract | `SMART_CONTRACT` | ❌ Manual handling |
| Other / ASN | `OTHER` | ⚠️ Confirm first |

### 1.2 Three-state eligibility (submission × bounty)

| Submission | Bounty | Meaning | Action |
| --- | --- | --- | --- |
| true | true | In scope and bounty eligible | Test normally |
| true | false | **In scope but not bounty eligible** | Test normally; do not skip |
| false | — | **Out of scope** | **Never touch it** |

### 1.3 Pasted scope table shape (lenient parsing)

```
In scope:
https://api.example.com        | URL       | Eligible for bounty
*.example.com                  | WILDCARD  | Eligible for bounty
app.example.com                | URL       | In scope, NOT bounty-eligible
com.example.android            | GOOGLE_PLAY_APP_ID | Eligible for bounty

Out of scope:
blog.example.com               | URL
*.corp.example.com             | WILDCARD
```

Parsing rules:

- Extract at least the **asset identifier** and its in/out classification from
  every row. Identify the type and eligibility whenever possible.
- Column order and separators may vary (`|`, tabs, or multiple spaces); use
  lenient token matching.
- If a row's classification is uncertain, ask the user to confirm. **Never
  default an uncertain row to in-scope.**

## 2. Mandatory program rules

Check these rules before testing any asset:

- **No DoS or availability impact** — prohibit stress tests, resource
  exhaustion, and high-volume concurrency.
- **Rate and automation limits** — operate slowly and serially; follow any rule
  that prohibits automated scanning.
- **No social engineering** — do not target or phish people.
- **Minimal impact and no PII exfiltration** — stop after verification and do
  not export real user data.
- These rules supplement VulnClaw's existing `BLOCKED_PATTERNS` and
  `RESERVED_IP_RANGES` protections.

## 3. HackerOne submission report template

Use this structure for each finding:

```markdown
### [Title] <vulnerability type> on <asset>

**Asset:** <affected in-scope asset (URL or identifier)>

**Severity (CVSS):** <Critical | High | Medium | Low> —
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (score: X.X)

**Steps to Reproduce:**
1. <step, including request, response, or payload>
2. ...

**Impact:**
<exploitability and business impact>

**Remediation:**
<recommended fix>

**Proof of Concept:**
<parameterized Python PoC using requests; verification only, with no destructive action>
```

Reports are for the user to **submit manually** on HackerOne. The Skill never
submits reports automatically.
