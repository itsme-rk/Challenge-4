# REPORT.md — remcheck v0.1.0

---

## Part A — Threat Modelling the Fix

### Q1: What is insecure deserialization and why did it lead to RCE?

Java deserialization reconstructs a Java object from a byte stream. The danger
is that Java calls readObject() automatically during reconstruction before
application code runs. An attacker crafts a byte stream that triggers a chain
of method calls through existing classes on the server classpath — called gadget
chains. In FIND-0139, the CommonsCollections6 gadget chain abused Apache Commons
Collections to call Runtime.exec(), executing OS commands. The server accepted
the payload via POST /api/v1/session/restore with Content-Type
application/x-java-serialized-object, deserialized it without validation, and
RCE was confirmed via OOB HTTP callback.

### Q2: Five ways the class-check fix could be bypassed

| # | Bypass | Mechanism |
|---|--------|-----------|
| 1 | Whitelisted class as gadget entry point | java.util.HashMap allowed but routes through malicious chain |
| 2 | Class name spoofing via ClassLoader | Stream references class names passing string check but resolving differently |
| 3 | Nested/wrapped objects | Outer class whitelisted but unchecked malicious nested object fires chain |
| 4 | Alternative serialization formats | Kryo, Hessian, XStream bypass the Java-native class check entirely |
| 5 | Different endpoints | Other API paths deserialize without applying the same filter |

### Q3: Three measurable conditions for successful fix

1. All gadget chain payloads return HTTP 400 with response time under 1 second
   confirming rejection before deserialization starts
2. Zero OOB callbacks within 30 minutes after sending any malicious payload
3. Benign serialized objects still accepted with HTTP 200 confirming feature works

### Q4: Does updating Commons Collections 4.1 eliminate the risk?

No. It removes CC1-CC7 gadget chains but does not fix the root cause of
deserializing untrusted data. Spring, Groovy, and JRE gadget chains remain.
Alternative serialization formats are unaffected. It is defense-in-depth, not a fix.

---

## Part B — Test Case Design

| Test ID | Category | Payload Description | Expected Vulnerable | Expected Fixed | Pass Condition |
|---------|----------|--------------------|--------------------|----------------|----------------|
| TC-01 | Gadget Chain Replay | CommonsCollections6 aced0005 | HTTP 200, 6s delay | HTTP 400, under 1s | Status 400 AND time under 1s |
| TC-02 | Control Test | Benign java.lang.Long object | HTTP 200 accepted | HTTP 200 accepted | Status 200 — feature works |
| TC-03 | Malformed Stream | Invalid magic bytes deadbeef | HTTP 400 or 500 | HTTP 400 | Not 200, no OOB |
| TC-04 | Alternative Chain | Spring Framework gadget chain | HTTP 200, 6s delay | HTTP 400, under 1s | Status 400 AND time under 1s |
| TC-05 | Class Name Manipulation | HashMap wrapping malicious nested object | HTTP 200 bypass | HTTP 400 | No OOB callback |
| TC-06 | Alternative Format | Hessian-serialized payload | HTTP 200 deserialized | HTTP 400 | Status 400 |
| TC-07 | OOB DNS Callback | CC6 triggering DNS to canary subdomain | DNS hit received | No DNS hit | Zero DNS callbacks in 30min |
| TC-08 | Groovy Gadget Chain | Groovy runtime chain no Commons Collections | HTTP 200 if Groovy present | HTTP 400 | No OOB |
| TC-09 | File Write Sink | CC chain targeting FileOutputStream | HTTP 200 file written | HTTP 400 | Status 400 AND time under 1s |
| TC-10 | Class-Check Depth | Whitelisted class wrapping gadget | HTTP 200 bypass | HTTP 400 recursive check | No OOB |

TC-02 is the most important control — if it fails the fix broke the feature entirely.
TC-04 directly answers whether the Commons Collections upgrade alone was sufficient.

---

## Part C — AI Integration Layer

Option chosen: Option 2 — Result Analyzer

After deterministic tests complete, results are sent to Llama 3.1 8B via Groq
API for advisory analysis. Response stored as separate ai_analysis field.
Cannot override verdict field. See prompts.md for full documentation.

Validation logic:
```python
verdict = compute_verdict(test_results)        # deterministic, never modified
ai_analysis = get_ai_analysis(...)             # advisory only
report["ai_analysis"] = ai_analysis            # separate field
# report["verdict"] never touched after compute_verdict()
```

---

## Part D — Demo Output

### Vulnerable server run
```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post
Timestamp : 2026-03-18T09:05:41Z
Retries   : 3 per test (Bonus B)

[TC-01] CommonsCollections6 gadget chain
        Status: 200 | Time: 6.013s | OOB: NO | Result: FAIL
        [ANOMALY] BEHAVIORAL: status 200 (expected 400)
        [ANOMALY] TEMPORAL: 6.013s exceeds 5s threshold
        Consistency: 3/3 CONSISTENT_FAIL

[TC-02] Benign serialized object (control)
        Status: 200 | Time: 0.010s | OOB: NO | Result: PASS
        Consistency: 0/3 CONSISTENT_PASS

[TC-03] Invalid magic bytes
        Status: 400 | Time: 0.005s | OOB: NO | Result: PASS
        Consistency: 0/3 CONSISTENT_PASS

[TC-04] Spring gadget chain
        Status: 200 | Time: 6.008s | OOB: NO | Result: FAIL
        [ANOMALY] BEHAVIORAL: status 200 (expected 400)
        [ANOMALY] TEMPORAL: 6.008s exceeds 5s threshold
        Consistency: 3/3 CONSISTENT_FAIL

===== VERDICT: REMEDIATION_FAILED =====
Failed Tests: 2/4
Report hash: sha256:e3a7b692a139bd9d0757175fca280f247b3b37ac18b48db2d3476fa262c2e74b
```

### Fixed server run
```
[TC-01] Status: 400 | Time: 0.012s | Result: PASS | 0/3 CONSISTENT_PASS
[TC-02] Status: 200 | Time: 0.008s | Result: PASS | 0/3 CONSISTENT_PASS
[TC-03] Status: 400 | Time: 0.004s | Result: PASS | 0/3 CONSISTENT_PASS
[TC-04] Status: 400 | Time: 0.007s | Result: PASS | 0/3 CONSISTENT_PASS

===== VERDICT: REMEDIATION_VERIFIED =====
Failed Tests: 0/4
Report hash: sha256:436f7135e12b5b93fe9aed51f1daadca1119955fe304add2468d9bde8b55c056
```

---

## Part E — Systems Design Under Pressure (150-200 words)

Each test is assigned a unique correlation ID embedded in its canary subdomain
at launch — for example tc042-find0139.oob.platform.com. All test records are
written to a persistent store such as Redis or PostgreSQL with status PENDING
and a finalization deadline of launch time plus 45 minutes, accounting for
30-minute DNS TTL drift plus margin.

A separate callback listener receives OOB hits and updates the store keyed by
correlation ID to CALLBACK_RECEIVED. No test is finalized while its deadline
is in the future. A finalization worker runs at 6 AM and closes only tests
whose deadline has passed. Tests still PENDING at deadline are marked
NO_CALLBACK. A finding is marked REMEDIATION_FAILED only if CALLBACK_RECEIVED
is set. Late callbacks arriving after the deadline are logged but do not reopen
closed findings — they are queued for analyst review separately. The morning
report aggregates all finalized records grouped by finding ID, producing one
consolidated verdict per finding regardless of callback arrival order.

---

## Bonus B — Retry and Consistency Engine

Each test runs 3 times. Consistency score reports failure count across runs.
CONSISTENT_FAIL 3/3 means high confidence vulnerable. CONSISTENT_PASS 0/3
means high confidence fixed. INCONSISTENT 1/3 or 2/3 means INCONCLUSIVE,
flagged for manual review. Directly implements the challenge requirement of
reporting FAIL 3/3 consistent vs FAIL 1/3 inconsistent flag for review.

---

## Honest Self-Assessment

### What works
- Full test suite with hex and base64 payload decoding
- Three-signal anomaly detection: behavioral, temporal, content
- Bonus B retry engine with consistency scoring across 3 runs
- Tamper-evident SHA-256 report hashing
- Mock server simulating both vulnerable and fixed server states
- Clean CLI with color, --quiet, --verbose, exit codes 0/1/2
- AI advisory analysis via Groq Llama 3.1 8B with real output

### What is missing or limited
- OOB callback detection requires a real canary platform such as Interactsh.
  Current implementation polls a placeholder URL only.
- Mock server simulates timing behavior only and does not execute real gadget
  chains. A real Java target needed for genuine OOB callbacks.
- Only 4 of 10 designed test cases are automated. TC-05 through TC-10 require
  a real Java runtime to execute meaningfully.

### What I would do differently with more time
- Build a real vulnerable Java server using Spring Boot with outdated Commons
  Collections enabling genuine gadget chain execution and real OOB callbacks
- Implement all 10 test cases from Part B
- Integrate Interactsh as live OOB canary platform
- Add async batching for AI analysis to handle rate limits properly
