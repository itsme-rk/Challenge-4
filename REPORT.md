# REPORT.md — remcheck v0.1.0

---

## Part A — Threat Modelling the Fix

### 1. What is insecure deserialization and why did it lead to RCE?

Java deserialization is the process of reconstructing a Java object from a byte
stream. The danger is that Java calls certain methods automatically during this
reconstruction, specifically readObject(), before your application code ever runs.
An attacker doesn't need to supply a valid object your app understands — they just
need a crafted byte stream that, when deserialized, triggers a chain of method calls
through existing classes already on the server's classpath. These chains are called
gadget chains.

In FIND-0139, the attacker used the CommonsCollections6 gadget chain, a well-known
chain that abuses classes in Apache Commons Collections to ultimately call
Runtime.exec(), executing arbitrary OS commands. The server accepted the serialized
payload via POST /api/v1/session/restore with Content-Type:
application/x-java-serialized-object, deserialized it without validation, and the
gadget chain fired — executing curl http://attacker.com/proof, confirmed via OOB
HTTP callback. RCE was achieved entirely through the deserialization mechanism, not
through any logic bug in the application itself.

---

### 2. Five ways the class-check fix could be incomplete or bypassed

| # | Bypass | Mechanism |
|---|--------|-----------|
| 1 | Gadget chain using a whitelisted class | If java.util.HashMap is allowed, attackers use it as the entry point for chains like CommonsCollections that route through permitted classes |
| 2 | Class name spoofing via custom ClassLoader | A crafted stream can reference class names that pass the string check but resolve differently at load time via a malicious ClassLoader |
| 3 | Nested/wrapped objects | The outer object's class may be whitelisted, but it contains a nested malicious object whose class is never checked independently |
| 4 | Alternative serialization formats | The class check only applies to Java serialization (0xACED magic bytes); payloads using Kryo, Hessian, or XStream bypass it entirely if those deserializers are also present |
| 5 | Different endpoints using same deserializer | Other API endpoints or internal job processors may deserialize objects without applying the same class-check filter |

---

### 3. Three measurable conditions for a successful fix

a. All gadget chain payloads return HTTP 400 before deserialization occurs —
specifically, rejection must happen at the input validation layer, not after
deserialization starts. This is measurable via response time: if deserialization
ran, response time will be elevated well above baseline.

b. Zero OOB callbacks received within a 30-minute window after sending any
malicious payload to any endpoint, confirming no code execution path was triggered.

c. Benign serialized objects of explicitly allowed classes are still accepted with
HTTP 200, confirming the fix didn't simply break the feature entirely.

---

### 4. Does updating Commons Collections 4.1 eliminate the risk?

No. Updating to Commons Collections 4.1 removes the specific gadget chains that
exploit known vulnerable method chains in that library. It directly addresses
CommonsCollections1 through CommonsCollections7 gadget chains. However, it does not:

- Prevent gadget chains from other libraries on the classpath (Spring Framework,
  Groovy, JRE built-ins like java.rmi)
- Fix the root cause: the application still deserializes untrusted data
- Protect against future gadget chain discoveries in Commons Collections 4.1 itself
- Address alternative serialization formats like Kryo or Hessian

The library update is a useful defense-in-depth measure but is not a fix. The
correct remediation is to either avoid deserializing untrusted data entirely, use
a serialization format that cannot carry executable code (JSON/protobuf), or
implement a strict allowlist with an ObjectInputFilter that rejects deserialization
before any gadget chain can trigger.

---

## Part B — Test Case Design

| Test ID | Category | Payload Description | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
|---------|----------|--------------------|-----------------------|------------------|----------------|
| TC-01 | Gadget Chain Replay | Original CommonsCollections6 gadget chain (aced0005...) — exact payload from original finding | HTTP 200, OOB callback received, RCE confirmed | HTTP 400, no OOB callback, response time < 1s | Status 400 AND no OOB hit within 30s AND response time < 1s |
| TC-02 | Alternative Gadget Chain | Spring Framework gadget chain (spring-core) targeting ProcessBuilder — does not use Commons Collections at all | HTTP 200, OOB callback received | HTTP 400, no OOB callback | Status 400 AND no OOB hit — directly tests whether library update alone was sufficient |
| TC-03 | Class-Check Enforcement | Serialized object with class name java.util.HashMap (whitelisted) wrapping a malicious nested CommonsCollections6 inner object | HTTP 200, RCE via nested object | HTTP 400 or deserialization of outer object with inner object stripped/rejected | No OOB callback AND response time < 1s — specifically validates class-check depth |
| TC-04 | Class Name Manipulation | Serialized stream with a class name crafted to resemble a safe class (e.g. java.util.HashMap$Entry spoofed to bypass string match) | HTTP 200, bypass class filter, OOB callback | HTTP 400, class-check catches manipulation | Status 400 AND no OOB hit — tests string-matching weakness in class-check logic |
| TC-05 | Alternative Serialization Format | Hessian-serialized payload containing equivalent gadget chain logic (non-Java 0xACED format) | HTTP 200 or deserialized without class-check | HTTP 400 or ignored | Status 400 — tests whether class-check only applies to Java native serialization |
| TC-06 | OOB DNS Callback | CommonsCollections6 chain modified to trigger DNS lookup to unique canary subdomain tc06.find0139.oob.yourplatform.com instead of HTTP | DNS hit received, RCE confirmed without relying on response body | No DNS hit within 30 min window | Zero DNS callbacks to canary domain — confirms no execution path even with delayed callbacks |
| TC-07 | Benign Control Object | Valid serialized java.lang.Long object — safe class, safe content, correct magic bytes | HTTP 200, object processed normally | HTTP 200, object processed normally | Status 200 — confirms fix didn't break legitimate deserialization entirely |
| TC-08 | Malformed Stream | Payload with invalid magic bytes (deadbeef instead of aced0005) | HTTP 400 or 500, error handling triggered | HTTP 400, graceful rejection | Status 400 or 500 (not 200) AND no OOB callback — tests error handling path |
| TC-09 | Groovy Gadget Chain | Groovy runtime gadget chain — tests a library entirely unrelated to Commons Collections or Spring | HTTP 200, OOB callback if Groovy on classpath | HTTP 400 or no OOB callback | No OOB callback — tests whether fix is gadget-chain-specific or a true root fix |
| TC-10 | File Write Sink | CommonsCollections gadget chain targeting file write sink (FileOutputStream) instead of command execution | HTTP 200, file written to server | HTTP 400, no file write | Status 400 AND response time < 1s — tests different execution sink, not just Runtime.exec() |

**Note on TC-07:** This is the most critical control test. If it fails on the fixed
server it means the fix broke legitimate deserialization entirely, which is a
different problem.

**Note on TC-02:** Directly answers whether the Commons Collections 4.1 upgrade
alone would have been sufficient. If the Spring chain produces a callback, the
answer is definitively no.

---

## Part C — AI Integration Layer

**Option chosen: Option 2 — Result Analyzer**

After the deterministic engine finishes, the full test result set is sent to
Llama 3.1 8B (via Groq API) for advisory analysis. The LLM looks at status codes,
response times, OOB hits, consistency scores, and anomalies across all tests and
gives its read on whether the fix looks complete, partial, or bypassed.

The important constraint: the LLM output is stored as a completely separate field
called `ai_analysis` in the evidence JSON. The `verdict` field is computed before
the AI call ever happens and is never touched again afterward. No matter what the
LLM says, the verdict stays deterministic.

```python
# This is the actual order in main()
verdict     = compute_verdict(test_results)   # runs first, locked in
ai_analysis = get_ai_analysis(...)            # runs after, advisory only
report["ai_analysis"] = ai_analysis           # separate field, never touches verdict
```

The actual AI output we got on the fixed server run:

> "The remediation appears complete as all test cases TC-01 to TC-04 resulted
> in a PASS status with no anomalies. TC-01 and TC-04 are the most significant —
> these validate effectiveness against known exploitation paths. Residual risk
> may exist as new gadget chains or exploitation paths could emerge. Recommended
> next steps: continuously monitor for new deserialization vulnerabilities,
> conduct regular security testing, and consider implementing Java deserialization
> filtering as an additional control."

See prompts.md for the full prompt, raw output, and critique.

---

## Part D — Demo Output

We built a local Python Flask mock server (`src/mock_server.py`) that simulates
the target Java server in two modes — vulnerable and fixed. This let us test
without needing a real Java environment or internet connection.

### Run 1: Vulnerable server (`python3 src/mock_server.py --mode vulnerable`)

In vulnerable mode the server sleeps 6 seconds and returns HTTP 200 for gadget
chain payloads, simulating deserialization executing before any rejection logic.

```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post
Timestamp : 2026-03-18T09:05:41Z
Retries   : 3 per test (Bonus B consistency engine)

[TC-01] Description : CommonsCollections6 gadget chain
         Status       : 200 | Time: 6.013s | OOB Callback: NO
         Result       : FAIL
         [ANOMALY] BEHAVIORAL: status 200 (expected 400)
         [ANOMALY] TEMPORAL: response time 6.013s exceeds 5s threshold
         Consistency  : 3/3 — CONSISTENT_FAIL

[TC-02] Description : Benign serialized object (control)
         Status       : 200 | Time: 0.010s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Control test accepted as expected

[TC-03] Description : Invalid magic bytes
         Status       : 400 | Time: 0.005s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Malformed stream correctly rejected

[TC-04] Description : Spring gadget chain
         Status       : 200 | Time: 6.008s | OOB Callback: NO
         Result       : FAIL
         [ANOMALY] BEHAVIORAL: status 200 (expected 400)
         [ANOMALY] TEMPORAL: response time 6.008s exceeds 5s threshold
         Consistency  : 3/3 — CONSISTENT_FAIL

===== VERDICT: REMEDIATION_FAILED =====
Failed Tests  : 2/4
Report hash   : sha256:e3a7b692...
```

TC-01 and TC-04 fail because the mock server returns 200 after a 6 second delay,
triggering both behavioral and temporal anomalies. Both fail consistently across
all 3 retry runs, giving a CONSISTENT_FAIL score which means high confidence —
this is not a fluke.

### Run 2: Fixed server (`python3 src/mock_server.py --mode fixed`)

In fixed mode the server checks the payload against known gadget chain signatures
and immediately returns HTTP 400 with `class_not_in_allowlist` before doing
anything else.

```
[TC-01] Description : CommonsCollections6 gadget chain
         Status       : 400 | Time: 0.012s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS

[TC-02] Description : Benign serialized object (control)
         Status       : 200 | Time: 0.008s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS
         Control test accepted as expected

[TC-03] Description : Invalid magic bytes
         Status       : 400 | Time: 0.004s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS
         Malformed stream correctly rejected

[TC-04] Description : Spring gadget chain
         Status       : 400 | Time: 0.007s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS

===== VERDICT: REMEDIATION_VERIFIED =====
Failed Tests  : 0/4
Report hash   : sha256:436f7135...
```

All four pass. The key thing to notice: TC-02 still returns 200 (the benign object
is accepted) while TC-01 and TC-04 now return 400. This is the correct behavior —
the fix blocks gadget chains without breaking the feature.

---

## Part E — Systems Design Under Pressure

The question asks how to handle 500 overnight tests where OOB callbacks can arrive
up to 30 minutes late due to DNS TTL.

Each test gets a unique correlation ID embedded directly in the canary subdomain
before launch, something like `tc-042-find0139.oob.platform.com`. Every test
record is written to a store immediately with status PENDING and a deadline of
launch time plus 45 minutes — that 45 minute window accounts for the 30 minute
maximum DNS delay plus a 15 minute buffer.

A callback listener runs continuously and writes any incoming OOB hit to the
same store keyed by correlation ID. No test result is finalized while its deadline
is still in the future — this is what prevents premature closure.

A finalization job runs at 6 AM and sweeps only tests whose deadline has passed.
At that point: if the store shows CALLBACK_RECEIVED, the finding is marked
REMEDIATION_FAILED. If it still shows PENDING, it gets marked NO_CALLBACK and
the finding is REMEDIATION_VERIFIED. Any callback that arrives after the deadline
is logged separately and flagged for analyst review but does not reopen the closed
finding.

The morning report groups all finalized results by finding ID and produces one
verdict per finding regardless of what order the callbacks arrived in overnight.

---

## Bonus B — Retry and Consistency Engine

The challenge requirement says: report "FAIL (3/3 consistent)" vs
"FAIL (1/3 inconsistent - flag for review)".

Every test in our engine runs 3 times instead of once. After all 3 runs, the
consistency engine counts how many runs produced a failure signal (wrong status
code, response time over 5 seconds, or OOB callback). The score is reported as
failures/total:

- `3/3 CONSISTENT_FAIL` — all three runs failed, high confidence the vulnerability
  is still present
- `0/3 CONSISTENT_PASS` — all three runs passed, high confidence the fix is holding
- `1/3 or 2/3 INCONSISTENT` — mixed results, verdict set to INCONCLUSIVE and
  flagged for manual review

In our vulnerable server run, TC-01 and TC-04 both showed 3/3 CONSISTENT_FAIL,
which means the REMEDIATION_FAILED verdict is reliable, not a one-off anomaly.

---

## Honest Self-Assessment

### What works

- Payload decoding for both hex and base64 formats
- HTTP requests with correct Content-Type header
- Three-signal anomaly detection: behavioral (wrong status), temporal
  (response over 5 seconds), content (canary string in body)
- Bonus B retry engine running each test 3 times with consistency scoring
- SHA-256 hash of the evidence report for tamper-evidence
- Local Flask mock server that accurately simulates vulnerable and fixed
  server behavior
- Clean terminal output with color, --quiet flag, --verbose flag
- Exit codes 0/1/2 for pipeline integration
- AI advisory analysis via Groq (Llama 3.1 8B) with real output in evidence JSON

### What is missing or limited

- **OOB callback detection is not live.** The code polls a placeholder URL.
  To get real OOB hits you need a real canary platform like Interactsh or
  Burp Collaborator AND a real Java server that actually executes the payload.
  Our mock server simulates the timing of deserialization but doesn't run
  actual Java code, so it can't phone home to any canary domain.

- **Only 4 of the 10 designed test cases are automated.** TC-01 through TC-04
  map to the payloads in deserial_example.json. The remaining six test cases
  from Part B (Hessian format, DNS OOB, Groovy chain, file write sink, etc.)
  are designed but not implemented because they require a real Java runtime
  to execute meaningfully. Running them against the mock server would produce
  meaningless results.

- **The mock server is Python, not Java.** It accurately simulates the response
  behavior (status codes and timing) but doesn't run real gadget chains. A
  real end-to-end test would need a Spring Boot application with outdated
  Commons Collections on the classpath.

### What I would do differently with more time

- Build an actual vulnerable Java server using Spring Boot with an intentionally
  outdated Commons Collections version, so real ysoserial payloads could be
  fired and genuine OOB callbacks could be captured
- Set up Interactsh as the canary platform for real DNS and HTTP callback detection
- Implement all 10 test cases from Part B in the automated suite
- Fix the AI rate limiting properly with async batching instead of a fallback
