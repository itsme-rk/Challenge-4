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

## The prompt we used
 
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
 
## Raw AI output (unedited)
 
```python
import requests
import base64
import time
import json
 
def verify_deserialization(config):
    results = []
    
    for payload in config["payloads"]:
        # Decode payload
        if payload["encoding"] == "base64":
            data = base64.b64decode(payload["data"])
        else:
            data = bytes.fromhex(payload["data"])
        
        # Send request
        response = requests.post(
            config["target"],
            data=data,
            headers={"Content-Type": config["content_type"]}
        )
        
        # Wait for OOB
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
 
## Critique of raw AI output
 
The AI output was a reasonable starting point but had multiple problems that
made it incomplete and unsafe to use directly:
 
**1. No error handling anywhere.**
If the target is unreachable, `requests.post()` throws an exception and the
entire function crashes. There is no try/except block. In a security tool
running against potentially unresponsive targets, this is a critical gap.
 
**2. No timing anomaly detection.**
The spec explicitly requires detecting response times greater than 5 seconds
as a signal that deserialization was triggered. The raw output records nothing
about response time at all.
 
**3. OOB polling logic is broken.**
The function polls the OOB URL once after every test with a flat 10 second
sleep. This does not correlate the callback to the specific test that triggered
it. If TC-01 triggers a callback that arrives during TC-03's polling window,
it gets attributed to TC-03 instead.
 
**4. No payload encoding validation.**
The function assumes encoding is either "base64" or "hex" but has no else
branch. If an unknown encoding is passed, bytes.fromhex() gets called on a
base64 string and throws a ValueError with no useful error message.
 
**5. Missing behavioral anomaly check.**
The function records the status code but never compares it against
expected_rejection_code. It cannot determine pass or fail — it just
returns raw numbers with no verdict logic.
 
**6. No consistency/retry logic.**
A single test run can produce false positives from network jitter. The spec
(Bonus B) requires running each test multiple times and reporting consistency.
The raw output has no retry mechanism whatsoever.
 
**7. Result schema is too minimal.**
The returned dict only has id, status, and oob. Missing: response time,
body snippet, anomaly list, pass/fail result, and consistency data.
 
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
 
## Additional AI integration: Result Analyzer (Option 2)
 
We also implemented Option 2 — sending completed test results to Llama 3.1 8B
via Groq API for advisory analysis after the deterministic engine finishes.
The LLM output is stored as a separate `ai_analysis` field and cannot override
the verdict.
 
```python
verdict     = compute_verdict(test_results)    # deterministic, locked in
ai_analysis = get_ai_analysis(...)             # advisory only, runs after
report["ai_analysis"] = ai_analysis            # separate field
# report["verdict"] is never touched again
```
 
**API issues encountered and fixed during development:**
- Gemini (Google AI Studio) hit 429 rate limits immediately on free tier
- Groq with model `llama3-8b-8192` returned `model_decommissioned` error
  — confirmed via curl, fixed by switching to `llama-3.1-8b-instant`
- urllib returned 403 despite valid API key (Authorization header stripped
  on redirect) — fixed by switching to `requests` library
 
---
 
## Actual AI analysis output — REMEDIATION_FAILED run
 
This is the real output from the Groq API call during the vulnerable server run:
 
```
Advisory Analysis: FIND-0139
 
1. Fix completeness: The remediation appears to be partial, as two test
cases (TC-01 and TC-04) still trigger the vulnerability, while TC-02 and
TC-03 pass as expected.
 
2. Most significant test results: TC-01 and TC-04 are the most significant,
as they both demonstrate exploitation using different gadget chains. The
behavioral anomalies (status 200 instead of 400) and temporal anomalies
(exceeding the 5s threshold) indicate deserialization is likely triggered.
 
3. Residual risk: The presence of two failing test cases indicates the
vulnerability is still exploitable. Further analysis and testing required.
 
4. Recommended next steps: Investigate the root cause of the partial
remediation, review the implementation, and re-test after additional fixes.
```
 
**Critique of this AI output:**
- The LLM correctly identified TC-01 and TC-04 as critical failures
- It did not attempt to override the deterministic REMEDIATION_FAILED verdict
- However it called the fix "partial" — the correct description is that the
  class-check is not working at all, both gadget chains passed through
- It ignored the 3/3 CONSISTENT_FAIL score entirely — this is the strongest
  signal in the data and confirms the result is not network jitter
- "Further analysis required" is vague; a better recommendation would name
  specific next steps: deploy ObjectInputFilter at JVM level, test all
  endpoints that accept serialized objects, not just this one
 
---
 
## Evidence files
 
Both evidence JSON files are in the evidence/ directory:
 
**FIND-0139_20260319T124149Z.json** — Vulnerable server run
- Verdict: REMEDIATION_FAILED
- TC-01 and TC-04: status 200, ~6s response time, 3/3 CONSISTENT_FAIL
- AI analysis: completed via Groq
 
**FIND-0139_20260319T125842Z.json** — Fixed server run  
- Verdict: REMEDIATION_VERIFIED
- All 4 tests: status 400 (TC-01,03,04) and 200 (TC-02 control), <0.05s
- AI analysis: completed via Groq
- Report hash: sha256:cbfcd754f0585bea183ed07305ce5809041b9c492cc20556580eca9ef5f3d223
---

## Part D — Demo Output

We built a local Python Flask mock server (`src/mock_server.py`) that simulates
the target Java server in two modes — vulnerable and fixed. This let us test
without needing a real Java environment or internet connection.

code for the mock server - 
#!/usr/bin/env python3
# mock_server.py - Local vulnerable/fixed Java deserialization mock
# Run with: python3 src/mock_server.py [--mode vulnerable|fixed]
#
# vulnerable mode: simulates an unpatched server (returns 200 for gadget chains)
# fixed mode:      simulates a patched server (returns 400 for gadget chains)

import argparse
from datetime import datetime, timezone

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("[ERROR] Flask not found. Run: pip3 install flask")
    exit(1)

app = Flask(__name__)

# Gadget chain signatures — these hex prefixes identify known bad payloads
# Real Java serialized objects start with aced0005
KNOWN_GADGET_PREFIXES = [
    "aced000573720011",  # CommonsCollections6 (TC-01)
    "aced000573720012",  # Spring gadget chain (TC-04)
]

BENIGN_PREFIXES = [
    "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs=",  # base64 benign Long object
]

INVALID_MAGIC = [
    "deadbeef",  # not a valid Java serialized object
]

MODE = "vulnerable"  # default, overridden by --mode flag


@app.route("/api/v1/session/restore", methods=["POST"])
@app.route("/post", methods=["POST"])
def handle_post():
    raw_body = request.get_data()
    hex_body = raw_body.hex()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Check for invalid magic bytes — always reject these
    if hex_body.startswith("deadbeef"):
        return jsonify({
            "status": "rejected",
            "reason": "invalid_magic_bytes",
            "timestamp": timestamp
        }), 400

    # Check if it's a known gadget chain
    is_gadget = any(hex_body.startswith(p) for p in KNOWN_GADGET_PREFIXES)

    if is_gadget:
        if MODE == "vulnerable":
            # Simulate deserialization happening — slow response + 200
            import time
            time.sleep(6)  # triggers temporal anomaly (>5s threshold)
            return jsonify({
                "status": "deserialized",
                "message": "object processed",
                "timestamp": timestamp
            }), 200
        else:
            # Fixed mode — class-check fires before deserialization
            return jsonify({
                "status": "rejected",
                "reason": "class_not_in_allowlist",
                "timestamp": timestamp
            }), 400

    # Benign object — always accept
    return jsonify({
        "status": "accepted",
        "message": "valid object processed",
        "timestamp": timestamp
    }), 200


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock Java deserialization server")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "fixed"],
        default="vulnerable",
        help="vulnerable = simulates unpatched server, fixed = simulates patched server"
    )
    args = parser.parse_args()
    MODE = args.mode

    print(f"\n[mock_server] Starting in {MODE.upper()} mode")
    print(f"[mock_server] Listening on http://127.0.0.1:5000")
    print(f"[mock_server] Endpoints: POST /post  or  POST /api/v1/session/restore\n")


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


code for verify_deserial.py script

#!/usr/bin/env python3
# verify_deserial.py - Insecure Deserialization Remediation Verifier
# Part of remcheck v0.1.0

import json
import sys
import time
import uuid 
import hashlib
import base64
import argparse
import os
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[ERROR] requests library not found. Run: pip3 install requests")
    sys.exit(1)

# ─────────────────────────────────────────
# ANSI color codes with terminal fallback
# ─────────────────────────────────────────
def supports_color():
    return hasattr(sys.stdout, 'isatty' ) and sys.stdout.isatty()

GREEN  = "\033[92m" if supports_color() else ""
RED    = "\033[91m" if supports_color() else ""
YELLOW = "\033[93m" if supports_color() else ""
CYAN   = "\033[96m" if supports_color() else ""
BOLD   = "\033[1m"  if supports_color() else ""
RESET  = "\033[0m"  if supports_color() else ""

# ─────────────────────────────────────────
# Payload decoder
# ─────────────────────────────────────────
def decode_payload(encoding: str, data: str) -> bytes:
    # Decode hex or base64 payload into raw bytes
    if encoding == "hex":
        try:
            return bytes.fromhex(data)
        except ValueError as e:
            raise ValueError(f"Invalid hex data: {e}")
    elif encoding == "base64":
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Invalid base64 data: {e}")
    else:
        raise ValueError(f"Unknown encoding: {encoding}. Use 'hex' or 'base64'.")

# ─────────────────────────────────────────
# OOB callback checker
# ─────────────────────────────────────────
def check_oob_callback(oob_poll_url: str, timeout: int = 10) -> tuple:
    # Returns (hit_detected: bool, raw_response: str)
    if not oob_poll_url or "yourplatform.com" in oob_poll_url:
        return False, "OOB polling skipped (demo mode)"
    try:
        r = requests.get(oob_poll_url, timeout=timeout)
        body = r.text
        hit = r.status_code == 200 and (
            "hit" in body.lower() or "callback" in body.lower()
        )
        return hit, body
    except requests.RequestException as e:
        return False, f"OOB poll failed: {e}"

# ─────────────────────────────────────────
# Single test runner
# ─────────────────────────────────────────
def run_single_test(target, content_type, raw_bytes, oob_poll_url, expected_code):
    # Fire one payload and collect all signals
    start = time.time()
    try:
        response = requests.post(
            target,
            data=raw_bytes,
            headers={"Content-Type": content_type},
            timeout=15
        )
        elapsed     = round(time.time() - start, 3)
        status_code = response.status_code
        body        = response.text
    except requests.RequestException as e:
        elapsed = round(time.time() - start, 3)
        return {
            "status_code"  : 0,
            "response_time": elapsed,
            "body_snippet" : f"REQUEST FAILED: {e}",
            "oob_hit"      : False,
            "oob_body"     : "",
            "error"        : str(e)
        }

    # Wait briefly then poll OOB
    time.sleep(2)
    oob_hit, oob_body = check_oob_callback(oob_poll_url)

    return {
        "status_code"  : status_code,
        "response_time": elapsed,
        "body_snippet" : body[:200],
        "oob_hit"      : oob_hit,
        "oob_body"     : oob_body,
        "error"        : None
    }

# ─────────────────────────────────────────
# BONUS B — Retry + Consistency Engine
# ─────────────────────────────────────────
def run_with_retry(target, content_type, raw_bytes,
                   oob_poll_url, expected_code, retries=3, description=""):
    results = []
    for i in range(retries):
        r = run_single_test(
            target, content_type, raw_bytes, oob_poll_url, expected_code
        )
        results.append(r)
        if i < retries - 1:
            time.sleep(1)

    is_control = "control" in description.lower() or "benign" in description.lower()

    def is_fail(r):
        timing_anomaly  = r["response_time"] > 5.0
        oob_triggered   = r["oob_hit"]
        network_failure = (r["status_code"] == 0 and r.get("error") is not None)
        # Control tests are allowed to return 200 — don't flag as wrong status
        wrong_status = (
            not is_control and
            r["status_code"] != expected_code and
            r["status_code"] != 0
        )
        return timing_anomaly or oob_triggered or wrong_status or network_failure

    failure_runs  = [r for r in results if is_fail(r)]
    failure_count = len(failure_runs)
    score         = f"{failure_count}/{retries}"

    if failure_count == 0:
        flag = "CONSISTENT_PASS"
    elif failure_count == retries:
        flag = "CONSISTENT_FAIL"
    else:
        flag = "INCONSISTENT - FLAG FOR REVIEW"

    best_result = failure_runs[0] if failure_runs else results[0]

    consistency = {
        "runs"              : retries,
        "failures"          : failure_count,
        "score"             : score,
        "flag"              : flag,
        "all_response_times": [r["response_time"] for r in results],
        "all_status_codes"  : [r["status_code"]   for r in results]
    }

    return best_result, consistency

# ─────────────────────────────────────────
# Anomaly detector
# ─────────────────────────────────────────
def detect_anomalies(result, expected_code, description):
    # Check all three signal classes
    anomalies   = []
    is_control  = "control" in description.lower() or "benign" in description.lower()

    # Behavioral — skip for control test (it SHOULD return 200)
    if not is_control:
        if result["status_code"] != expected_code and result["status_code"] != 0:
            anomalies.append(
                f"BEHAVIORAL: status {result['status_code']} "
                f"(expected {expected_code})"
            )

    # Temporal — applies to all tests including control
    if result["response_time"] > 5.0:
        anomalies.append(
            f"TEMPORAL: response time {result['response_time']}s "
            f"exceeds 5s threshold — deserialization likely triggered"
        )

    # OOB callback — RCE confirmed
    if result["oob_hit"]:
        anomalies.append(
            "OOB CALLBACK: canary domain hit detected — code execution confirmed"
        )

    # Content: canary string in body
    if "find0139" in result.get("body_snippet", "").lower():
        anomalies.append(
            "CONTENT: canary string found in response body"
        )

    return anomalies

# ─────────────────────────────────────────
# Verdict logic
# ─────────────────────────────────────────
def compute_verdict(test_results):
    # Deterministic — AI analysis cannot override this
    any_fail         = any(t["result"] == "FAIL" for t in test_results)
    any_inconsistent = any(
        "INCONSISTENT" in t.get("consistency", {}).get("flag", "")
        for t in test_results
    )

    if any_fail:
        return "REMEDIATION_FAILED"
    elif any_inconsistent:
        return "INCONCLUSIVE"
    else:
        return "REMEDIATION_VERIFIED"
        
        
# ─────────────────────────────────────────
# Part C — AI Result Analyzer (Option 2)
# ─────────────────────────────────────────
def get_ai_analysis(test_results, verdict, finding_id):
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {
            "status"  : "skipped",
            "reason"  : "GROQ_API_KEY not set",
            "analysis": None
        }

    summary_lines = []
    for t in test_results:
        anomaly_str = "; ".join(t["anomalies"]) if t["anomalies"] else "none"
        consistency = t.get("consistency", {})
        summary_lines.append(
            f"- {t['test_id']} ({t['description']}): "
            f"status={t['status_code']}, time={t['response_time']}s, "
            f"result={t['result']}, "
            f"consistency={consistency.get('score','?')} ({consistency.get('flag','?')}), "
            f"anomalies=[{anomaly_str}]"
        )

    test_summary = "\n".join(summary_lines)

    prompt = (
        f"You are a security analysis assistant reviewing automated remediation verification results.\n\n"
        f"Finding ID: {finding_id}\n"
        f"Vulnerability type: Insecure Java Deserialization\n"
        f"Deterministic verdict from test engine: {verdict}\n\n"
        f"Test results:\n{test_summary}\n\n"
        f"Provide an advisory analysis covering:\n"
        f"1. Whether the fix appears complete, partial, or bypassed\n"
        f"2. Which specific test results are most significant and why\n"
        f"3. Any residual risk even if verdict is REMEDIATION_VERIFIED\n"
        f"4. Recommended next steps for the security team\n\n"
        f"Important: Your analysis is advisory only. Do not contradict or attempt "
        f"to override the deterministic verdict. Keep your response under 200 words."
    )

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security analysis assistant. Be concise and technical."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 400,
                "temperature": 0.3
            },
            timeout=30
        )
        response.raise_for_status()
        analysis = response.json()["choices"][0]["message"]["content"]

        return {
            "status"       : "completed",
            "model"        : "llama-3.1-8b-instant via Groq",
            "prompt"       : prompt,
            "analysis"     : analysis,
            "advisory_only": True,
            "note"         : "This analysis does not override the deterministic verdict"
        }

    except Exception as e:
        return {
            "status"  : "failed",
            "reason"  : str(e),
            "analysis": None
        }

# ─────────────────────────────────────────
# Report builder + SHA-256 hash
# ─────────────────────────────────────────
def build_report(finding, test_results, verdict):
    report = {
        "report_id"     : str(uuid.uuid4()),
        "finding_id"    : finding["finding_id"],
        "generated_at"  : datetime.now(timezone.utc).isoformat(),
        "engine_version": "0.1.0",
        "verdict"       : verdict,
        "test_results"  : test_results,
        "ai_analysis": None,
        "summary"       : {
            "total"      : len(test_results),
            "passed"     : sum(1 for t in test_results if t["result"] == "PASS"),
            "failed"     : sum(1 for t in test_results if t["result"] == "FAIL"),
            "inconclusive": sum(1 for t in test_results if t["result"] == "INCONCLUSIVE")
	
        }
    }
    # Hash computed BEFORE adding hash field, so it's reproducible
    report_json         = json.dumps(report, sort_keys=True)
    report["report_hash"] = "sha256:" + hashlib.sha256(
        report_json.encode()
    ).hexdigest()
    return report

# ─────────────────────────────────────────
# Save evidence
# ─────────────────────────────────────────
def save_evidence(report, output_dir, finding_id):
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{finding_id}_{ts}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    return filepath

# ─────────────────────────────────────────
# CLI printer
# ─────────────────────────────────────────
def print_result_line(tc, quiet, verbose):
    if quiet:
        return

    result      = tc["result"]
    color       = GREEN if result == "PASS" else RED if result == "FAIL" else YELLOW
    oob_str     = "YES" if tc.get("oob_hit", False) else "NO"
    consistency = tc.get("consistency", {})

    print(f"\n[{tc['test_id']}] Description : {tc['description']}")
    print(f"         Encoding     : {tc['encoding']}")
    print(f"         Status       : {tc['status_code']} | "
          f"Time: {tc['response_time']}s | OOB Callback: {oob_str}")
    print(f"         Result       : {color}{result}{RESET}")

    if tc.get("anomalies"):
        for a in tc["anomalies"]:
            print(f"         {RED}[ANOMALY]{RESET} {a}")

    if consistency:
        flag_color = YELLOW if "INCONSISTENT" in consistency.get("flag","") else GREEN
        print(f"         Consistency  : {consistency.get('score')} "
              f"— {flag_color}{consistency.get('flag')}{RESET}")

    # Spec-required special messages
    desc = tc["description"].lower()
    if result == "PASS":
        if "control" in desc or "benign" in desc:
            print(f"         {GREEN}Control test accepted as expected{RESET}")
        elif "magic" in desc or "malformed" in desc or "invalid" in desc:
            print(f"         {GREEN}Malformed stream correctly rejected{RESET}")

    # Verbose: full body
    if verbose:
        print(f"         Body snippet : {tc.get('body_snippet','')[:300]}")

    print("         " + "─" * 50)

# ─────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="remcheck - Automated Remediation Verifier v0.1.0"
    )
    parser.add_argument("--finding", required=True,
                        help="Path to finding JSON file")
    parser.add_argument("--output",  default="./evidence",
                        help="Output directory for evidence")
    parser.add_argument("--quiet",   action="store_true",
                        help="Show only final verdict")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full request/response details per test")
    parser.add_argument("--retries", type=int, default=3,
                        help="Retry count per test for Bonus B consistency engine")
    args = parser.parse_args()

    # Load finding
    try:
        with open(args.finding) as f:
            finding = json.load(f)
    except FileNotFoundError:
        print(f"{RED}[ERROR] Finding file not found: {args.finding}{RESET}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"{RED}[ERROR] Invalid JSON in finding file: {e}{RESET}")
        sys.exit(2)

    # Header
    if not args.quiet:
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"\n{BOLD}===== REMEDIATION VERIFICATION REPORT ====={RESET}")
        print(f"Finding   : {finding['finding_id']} ({finding['type']})")
        print(f"Target    : {finding['target']}")
        print(f"Timestamp : {current_time}")
        print(f"Strategy  : DeserializationVerifier")
        print(f"Retries   : {args.retries} per test (Bonus B consistency engine)")
        print(f"\nRunning {len(finding['payloads'])} test(s)...")

    # Run tests
    test_results = []

    for payload in finding["payloads"]:
        try:
            raw_bytes = decode_payload(payload["encoding"], payload["data"])
        except ValueError as e:
            print(f"{RED}[SKIP] {payload['id']}: {e}{RESET}")
            continue

        result, consistency = run_with_retry(
    		target        = finding["target"],
    		content_type  = finding["content_type"],
    		raw_bytes     = raw_bytes,
    		oob_poll_url  = finding.get("oob_poll_url", ""),
    		expected_code = finding["expected_rejection_code"],
    		retries       = args.retries,
    		description   = payload["description"]   # ← add this line
	)

        anomalies = detect_anomalies(
            result,
            finding["expected_rejection_code"],
            payload["description"]
        )

        if consistency["flag"] == "INCONSISTENT - FLAG FOR REVIEW":
            tc_result = "INCONCLUSIVE"
        elif anomalies:
            tc_result = "FAIL"
        else:
            tc_result = "PASS"

        tc = {
            "test_id"      : payload["id"],
            "description"  : payload["description"],
            "encoding"     : payload["encoding"],
            "status_code"  : result["status_code"],
            "response_time": result["response_time"],
            "body_snippet" : result["body_snippet"],
            "oob_hit"      : result["oob_hit"],
            "anomalies"    : anomalies,
            "result"       : tc_result,
            "consistency"  : consistency
        }
        test_results.append(tc)
        print_result_line(tc, args.quiet, args.verbose)

    # Verdict
    verdict       = compute_verdict(test_results)
    verdict_color = (GREEN if verdict == "REMEDIATION_VERIFIED" else
                     RED   if verdict == "REMEDIATION_FAILED"   else YELLOW)

    failed_tests  = sum(1 for t in test_results if t["result"] == "FAIL")
    total_tests   = len(test_results)

    # Part C — AI advisory analysis (never overrides verdict)
    ai_analysis = get_ai_analysis(test_results, verdict, finding["finding_id"])

    # Build + save report
    report = build_report(finding, test_results, verdict)
    report["ai_analysis"] = ai_analysis  # stored separately, advisory only
    filepath = save_evidence(report, args.output, finding["finding_id"])

    # Footer
    if not args.quiet:
        print(f"\n{BOLD}===== VERDICT: "
              f"{verdict_color}{verdict}{RESET}{BOLD} ====={RESET}")
        print(f"Failed Tests  : {failed_tests}/{total_tests}")
        print(f"Evidence saved: {filepath}")
        print(f"Report hash   : {report['report_hash'][:50]}...\n")
    else:
        print(f"{verdict_color}{verdict}{RESET}")

    exit_codes = {
        "REMEDIATION_VERIFIED": 0,
        "REMEDIATION_FAILED"  : 1,
        "INCONCLUSIVE"        : 2
    }
    sys.exit(exit_codes.get(verdict, 2))

if __name__ == "__main__":
    main()


code for deserial_example.json

{
  "finding_id": "FIND-0139",
  "type": "insecure_deserialization",
  "target": "http://127.0.0.1:5000/post",
  "target_note": "Local mock server. For real internet demo use https://httpbin.org/post (note: httpbin accepts all payloads so all tests show behavioral anomaly - use mock server for accurate FAIL/PASS demonstration)",
  "content_type": "application/x-java-serialized-object",
  "expected_rejection_code": 400,
  "canary_domain": "find0139.oob.yourplatform.com",
  "oob_poll_url": "https://oob.yourplatform.com/api/hits?token=find0139",
  "payloads": [
    {
      "id": "TC-01",
      "description": "CommonsCollections6 gadget chain",
      "encoding": "hex",
      "data": "aced000573720011"
    },
    {
      "id": "TC-02",
      "description": "Benign serialized object (control)",
      "encoding": "base64",
      "data": "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs="
    },
    {
      "id": "TC-03",
      "description": "Invalid magic bytes",
      "encoding": "hex",
      "data": "deadbeef0001"
    },
    {
      "id": "TC-04",
      "description": "Spring gadget chain",
      "encoding": "hex",
      "data": "aced000573720012"
    }
  ]
}


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
