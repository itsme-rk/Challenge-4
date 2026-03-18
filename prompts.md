# Part C — AI Integration Layer Documentation

## Option chosen: Option 2 — Result Analyzer

The AI component sends completed test results to Gemini 
after the deterministic engine finishes. The LLM provides advisory analysis only
and cannot override the verdict.

---

## Prompt used
```
You are a security analysis assistant reviewing automated remediation
verification results.

Finding ID: FIND-0139
Vulnerability type: Insecure Java Deserialization
Deterministic verdict from test engine: REMEDIATION_FAILED

Test results:
- TC-01 (CommonsCollections6 gadget chain): status=200, time=6.034s,
  oob=False, result=FAIL, anomalies=[BEHAVIORAL: status 200 (expected 400);
  TEMPORAL: response time 6.034s exceeds 5s threshold]
- TC-02 (Benign serialized object control): status=200, time=0.008s,
  oob=False, result=PASS, anomalies=[none]
- TC-03 (Invalid magic bytes): status=400, time=0.004s,
  oob=False, result=PASS, anomalies=[none]
- TC-04 (Spring gadget chain): status=200, time=6.008s,
  oob=False, result=FAIL, anomalies=[BEHAVIORAL: status 200 (expected 400);
  TEMPORAL: response time 6.008s exceeds 5s threshold]

Based on these results, provide an advisory analysis covering:
1. Whether the fix appears complete, partial, or bypassed
2. Which specific test results are most significant and why
3. Any residual risk even if verdict is REMEDIATION_VERIFIED
4. Recommended next steps for the security team

Important: Your analysis is advisory only. Do not contradict or attempt
to override the deterministic verdict. Keep your response under 200 words.
```

---

## Raw LLM output (unedited)
```
The remediation appears to have FAILED — the fix is either absent or
incomplete. Two critical findings support this:

TC-01 and TC-04 are the most significant results. Both gadget chains
(CommonsCollections6 and Spring Framework) returned HTTP 200 with response
times exceeding 6 seconds. The 6-second delay strongly indicates active
deserialization occurred before any rejection logic ran — the server
processed the malicious object rather than blocking it at input validation.

The class-check fix claimed by the client either: (a) was not deployed
to this endpoint, (b) only checks against a narrow allowlist that both
gadget chain entry-point classes satisfy, or (c) runs after deserialization
begins rather than before.

Positive signals: TC-02 (benign control) correctly returned 200 and TC-03
(invalid magic bytes) correctly returned 400, suggesting basic input handling
is functional.

Residual risk: Even if gadget chains are eventually blocked, the root
vulnerability — trusting and deserializing untrusted input — remains.
Migration to a safe serialization format (JSON/protobuf) is strongly advised.

Recommended next steps:
- Deploy the class-check filter to all deserialization entry points
- Implement ObjectInputFilter as a JVM-level defense
- Re-test after fix deployment
```

---

## Critique of raw LLM output

**What was good:**
- Correctly identified TC-01 and TC-04 as the most significant failures
- Correctly explained the 6s timing anomaly as evidence of deserialization executing
- Did not attempt to override the deterministic verdict
- Provided actionable next steps

**What was wrong or incomplete:**
1. The LLM said "fix is either absent or incomplete" but didn't distinguish
   between the two — for a client dispute this matters significantly
2. It assumed the timing delay was caused by deserialization without noting
   this is an inference, not a confirmed fact (could be network latency in
   a real scenario)
3. It did not mention Bonus B consistency data — the fact that TC-01 and TC-04
   failed 3/3 runs (CONSISTENT_FAIL) significantly strengthens the verdict
   and the LLM ignored this signal entirely
4. No mention of OOB callback absence — in a real scenario, absence of OOB
   callback despite 200 response could indicate deserialization triggered
   but execution was blocked, which is a partial fix scenario

**Improvement made:**
The final prompt was updated to explicitly include consistency scores in
the test summary passed to the LLM, so it has full signal context.
The system prompt was also updated to instruct the LLM to comment on
consistency data when present.

---

## Example of caught and corrected bad LLM output

**Bad output caught:** In an earlier prompt iteration without explicit
instructions, the LLM responded with:

> "Based on my analysis, I would revise the verdict to PARTIAL_REMEDIATION
> rather than REMEDIATION_FAILED, as the benign object was accepted correctly."

**Why this is wrong:** The spec explicitly states the LLM analysis is
advisory only and must not override the deterministic verdict. A
PARTIAL_REMEDIATION verdict does not exist in our verdict schema.
Accepting a benign object is the expected baseline behavior (TC-02 is
a control test) and has no bearing on whether malicious payloads are blocked.

**Correction applied:** Added to the prompt:
`"Important: Your analysis is advisory only. Do not contradict or attempt
to override the deterministic verdict."`
This eliminated the verdict-override behavior in all subsequent runs.

---

## Validation logic between LLM output and engine
```python
# AI analysis is stored as a SEPARATE field in the evidence report
# It is clearly labeled advisory_only: true
# The deterministic verdict field is computed before AI is called
# and is never modified after AI analysis completes

report["ai_analysis"] = ai_analysis  # separate field
# report["verdict"] is never touched after compute_verdict() runs
```

