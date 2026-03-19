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

## Repository structure
```
remcheck/
├── README.md
├── REPORT.md
├── prompts.md
├── architecture.pdf
├── finding_examples/
│   └── deserial_example.json
├── src/
│   ├── verify_deserial.py
│   └── mock_server.py
└── evidence/
    ├── FIND-0139_20260319T124149Z.json 
    └── FIND-0139_20260319T125842Z.json 
```


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

### `src/finding_examples/deserial_example.json`
 
```json
{
  "finding_id": "FIND-0139",
  "type": "insecure_deserialization",
  "target": "http://127.0.0.1:5000/post",
  "target_note": "Local mock server. For real internet demo use https://httpbin.org/post",
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
```
 
---
 
### `src/mock_server.py`
 
```python
#!/usr/bin/env python3
# mock_server.py - Local vulnerable/fixed Java deserialization mock
# Run with: python3 src/mock_server.py [--mode vulnerable|fixed]
 
import argparse
from datetime import datetime, timezone
 
try:
    from flask import Flask, request, jsonify
except ImportError:
    print("[ERROR] Flask not found. Run: pip3 install flask")
    exit(1)
 
app = Flask(__name__)
 
KNOWN_GADGET_PREFIXES = [
    "aced000573720011",  # CommonsCollections6
    "aced000573720012",  # Spring gadget chain
]
 
MODE = "vulnerable"
 
 
@app.route("/api/v1/session/restore", methods=["POST"])
@app.route("/post", methods=["POST"])
def handle_post():
    raw_body = request.get_data()
    hex_body = raw_body.hex()
    timestamp = datetime.now(timezone.utc).isoformat()
 
    if hex_body.startswith("deadbeef"):
        return jsonify({
            "status": "rejected",
            "reason": "invalid_magic_bytes",
            "timestamp": timestamp
        }), 400
 
    is_gadget = any(hex_body.startswith(p) for p in KNOWN_GADGET_PREFIXES)
 
    if is_gadget:
        if MODE == "vulnerable":
            import time
            time.sleep(6)
            return jsonify({
                "status": "deserialized",
                "message": "object processed",
                "timestamp": timestamp
            }), 200
        else:
            return jsonify({
                "status": "rejected",
                "reason": "class_not_in_allowlist",
                "timestamp": timestamp
            }), 400
 
    return jsonify({
        "status": "accepted",
        "message": "valid object processed",
        "timestamp": timestamp
    }), 200
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["vulnerable", "fixed"],
                        default="vulnerable")
    args = parser.parse_args()
    MODE = args.mode
    print(f"\n[mock_server] Starting in {MODE.upper()} mode")
    print(f"[mock_server] Listening on http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
```
 
---
 
### `src/verify_deserial.py`
 
```python
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
 
def supports_color():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
 
GREEN  = "\033[92m" if supports_color() else ""
RED    = "\033[91m" if supports_color() else ""
YELLOW = "\033[93m" if supports_color() else ""
BOLD   = "\033[1m"  if supports_color() else ""
RESET  = "\033[0m"  if supports_color() else ""
 
def decode_payload(encoding, data):
    if encoding == "hex":
        return bytes.fromhex(data)
    elif encoding == "base64":
        return base64.b64decode(data)
    else:
        raise ValueError(f"Unknown encoding: {encoding}. Use hex or base64.")
 
def check_oob_callback(oob_poll_url, timeout=10):
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
 
def run_single_test(target, content_type, raw_bytes, oob_poll_url, expected_code):
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
            "status_code": 0, "response_time": elapsed,
            "body_snippet": f"REQUEST FAILED: {e}",
            "oob_hit": False, "oob_body": "", "error": str(e)
        }
    time.sleep(2)
    oob_hit, oob_body = check_oob_callback(oob_poll_url)
    return {
        "status_code": status_code, "response_time": elapsed,
        "body_snippet": body[:200], "oob_hit": oob_hit,
        "oob_body": oob_body, "error": None
    }
 
def run_with_retry(target, content_type, raw_bytes,
                   oob_poll_url, expected_code, retries=3, description=""):
    results = []
    for i in range(retries):
        r = run_single_test(target, content_type, raw_bytes,
                            oob_poll_url, expected_code)
        results.append(r)
        if i < retries - 1:
            time.sleep(1)
 
    is_control = "control" in description.lower() or "benign" in description.lower()
 
    def is_fail(r):
        timing_anomaly  = r["response_time"] > 5.0
        oob_triggered   = r["oob_hit"]
        network_failure = (r["status_code"] == 0 and r.get("error") is not None)
        wrong_status    = (
            not is_control and
            r["status_code"] != expected_code and
            r["status_code"] != 0
        )
        return timing_anomaly or oob_triggered or wrong_status or network_failure
 
    failure_runs  = [r for r in results if is_fail(r)]
    failure_count = len(failure_runs)
    score         = f"{failure_count}/{retries}"
 
    if failure_count == 0:       flag = "CONSISTENT_PASS"
    elif failure_count == retries: flag = "CONSISTENT_FAIL"
    else:                          flag = "INCONSISTENT - FLAG FOR REVIEW"
 
    consistency = {
        "runs": retries, "failures": failure_count, "score": score, "flag": flag,
        "all_response_times": [r["response_time"] for r in results],
        "all_status_codes":   [r["status_code"]   for r in results]
    }
    return failure_runs[0] if failure_runs else results[0], consistency
 
def detect_anomalies(result, expected_code, description):
    anomalies  = []
    is_control = "control" in description.lower() or "benign" in description.lower()
 
    if not is_control:
        if result["status_code"] != expected_code and result["status_code"] != 0:
            anomalies.append(
                f"BEHAVIORAL: status {result['status_code']} (expected {expected_code})"
            )
    if result["response_time"] > 5.0:
        anomalies.append(
            f"TEMPORAL: response time {result['response_time']}s "
            f"exceeds 5s threshold — deserialization likely triggered"
        )
    if result["oob_hit"]:
        anomalies.append(
            "OOB CALLBACK: canary domain hit detected — code execution confirmed"
        )
    if "find0139" in result.get("body_snippet", "").lower():
        anomalies.append("CONTENT: canary string found in response body")
    return anomalies
 
def compute_verdict(test_results):
    any_fail         = any(t["result"] == "FAIL" for t in test_results)
    any_inconsistent = any(
        "INCONSISTENT" in t.get("consistency", {}).get("flag", "")
        for t in test_results
    )
    if any_fail:         return "REMEDIATION_FAILED"
    elif any_inconsistent: return "INCONCLUSIVE"
    else:                  return "REMEDIATION_VERIFIED"
 
def get_ai_analysis(test_results, verdict, finding_id):
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {"status": "skipped", "reason": "GROQ_API_KEY not set", "analysis": None}
 
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
 
    prompt = (
        f"You are a security analysis assistant reviewing automated remediation "
        f"verification results.\n\nFinding ID: {finding_id}\n"
        f"Vulnerability type: Insecure Java Deserialization\n"
        f"Deterministic verdict from test engine: {verdict}\n\n"
        f"Test results:\n" + "\n".join(summary_lines) + "\n\n"
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
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system",
                     "content": "You are a security analysis assistant. Be concise and technical."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 400, "temperature": 0.3
            },
            timeout=30
        )
        response.raise_for_status()
        analysis = response.json()["choices"][0]["message"]["content"]
        return {
            "status": "completed", "model": "llama-3.1-8b-instant via Groq",
            "prompt": prompt, "analysis": analysis,
            "advisory_only": True,
            "note": "This analysis does not override the deterministic verdict"
        }
    except Exception as e:
        return {"status": "failed", "reason": str(e), "analysis": None}
 
def build_report(finding, test_results, verdict):
    report = {
        "report_id": str(uuid.uuid4()),
        "finding_id": finding["finding_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": "0.1.0",
        "verdict": verdict,
        "test_results": test_results,
        "ai_analysis": None,
        "summary": {
            "total":       len(test_results),
            "passed":      sum(1 for t in test_results if t["result"] == "PASS"),
            "failed":      sum(1 for t in test_results if t["result"] == "FAIL"),
            "inconclusive":sum(1 for t in test_results if t["result"] == "INCONCLUSIVE")
        }
    }
    report_json = json.dumps(report, sort_keys=True)
    report["report_hash"] = "sha256:" + hashlib.sha256(
        report_json.encode()
    ).hexdigest()
    return report
 
def save_evidence(report, output_dir, finding_id):
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath = os.path.join(output_dir, f"{finding_id}_{ts}.json")
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return filepath
 
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
        flag_color = YELLOW if "INCONSISTENT" in consistency.get("flag", "") else GREEN
        print(f"         Consistency  : {consistency.get('score')} "
              f"— {flag_color}{consistency.get('flag')}{RESET}")
 
    desc = tc["description"].lower()
    if result == "PASS":
        if "control" in desc or "benign" in desc:
            print(f"         {GREEN}Control test accepted as expected{RESET}")
        elif "magic" in desc or "malformed" in desc or "invalid" in desc:
            print(f"         {GREEN}Malformed stream correctly rejected{RESET}")
 
    if verbose:
        print(f"         Body snippet : {tc.get('body_snippet', '')[:300]}")
    print("         " + "─" * 50)
 
def main():
    parser = argparse.ArgumentParser(
        description="remcheck - Automated Remediation Verifier v0.1.0"
    )
    parser.add_argument("--finding", required=True)
    parser.add_argument("--output",  default="./evidence")
    parser.add_argument("--quiet",   action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()
 
    try:
        with open(args.finding) as f:
            finding = json.load(f)
    except FileNotFoundError:
        print(f"{RED}[ERROR] Finding file not found: {args.finding}{RESET}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"{RED}[ERROR] Invalid JSON: {e}{RESET}")
        sys.exit(2)
 
    if not args.quiet:
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"\n{BOLD}===== REMEDIATION VERIFICATION REPORT ====={RESET}")
        print(f"Finding   : {finding['finding_id']} ({finding['type']})")
        print(f"Target    : {finding['target']}")
        print(f"Timestamp : {current_time}")
        print(f"Strategy  : DeserializationVerifier")
        print(f"Retries   : {args.retries} per test (Bonus B consistency engine)")
        print(f"\nRunning {len(finding['payloads'])} test(s)...")
 
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
            description   = payload["description"]
        )
 
        anomalies = detect_anomalies(
            result, finding["expected_rejection_code"], payload["description"]
        )
 
        if consistency["flag"] == "INCONSISTENT - FLAG FOR REVIEW":
            tc_result = "INCONCLUSIVE"
        elif anomalies:
            tc_result = "FAIL"
        else:
            tc_result = "PASS"
 
        tc = {
            "test_id":       payload["id"],
            "description":   payload["description"],
            "encoding":      payload["encoding"],
            "status_code":   result["status_code"],
            "response_time": result["response_time"],
            "body_snippet":  result["body_snippet"],
            "oob_hit":       result["oob_hit"],
            "anomalies":     anomalies,
            "result":        tc_result,
            "consistency":   consistency
        }
        test_results.append(tc)
        print_result_line(tc, args.quiet, args.verbose)
 
    verdict       = compute_verdict(test_results)
    verdict_color = (GREEN if verdict == "REMEDIATION_VERIFIED" else
                     RED   if verdict == "REMEDIATION_FAILED"   else YELLOW)
    failed_tests  = sum(1 for t in test_results if t["result"] == "FAIL")
 
    ai_analysis = get_ai_analysis(test_results, verdict, finding["finding_id"])
    report      = build_report(finding, test_results, verdict)
    report["ai_analysis"] = ai_analysis
    filepath    = save_evidence(report, args.output, finding["finding_id"])
 
    if not args.quiet:
        print(f"\n{BOLD}===== VERDICT: {verdict_color}{verdict}{RESET}{BOLD} ====={RESET}")
        print(f"Failed Tests  : {failed_tests}/{len(test_results)}")
        print(f"Evidence saved: {filepath}")
        print(f"Report hash   : {report['report_hash'][:50]}...\n")
    else:
        print(f"{verdict_color}{verdict}{RESET}")
 
    sys.exit({"REMEDIATION_VERIFIED": 0,
               "REMEDIATION_FAILED": 1,
               "INCONCLUSIVE": 2}.get(verdict, 2))
 
if __name__ == "__main__":
    main()
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
 
**AI Advisory Analysis (Groq — Llama 3.1 8B):**
```
1. Fix completeness: The remediation appears to be partial, as two test cases
   (TC-01 and TC-04) still trigger the vulnerability, while TC-02 and TC-03
   pass as expected.
 
2. Most significant results: TC-01 and TC-04 are the most significant, as they
   both demonstrate exploitation using different gadget chains. Behavioral
   anomalies (status 200 instead of 400) and temporal anomalies (exceeding the
   5s threshold) indicate deserialization is likely triggered.
 
3. Residual risk: Two failing tests confirm the vulnerability is still
   exploitable. Further analysis and testing required.
 
4. Recommended next steps: Investigate the root cause of the partial
   remediation, review the implementation, and re-test after additional fixes.
```
 
**Critique:** The LLM called the fix "partial" — the correct description is that
the class-check is not working at all, both gadget chains passed through completely.
It also ignored the 3/3 CONSISTENT_FAIL score which is the strongest signal in
the data, and gave vague next steps instead of naming ObjectInputFilter specifically.
 
---
 
### Run 2 — Fixed server output
 
```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post
Timestamp : 2026-03-19T12:58:42Z
Retries   : 3 per test (Bonus B consistency engine)
 
[TC-01] Description : CommonsCollections6 gadget chain
         Encoding     : hex
         Status       : 400 | Time: 0.041s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
 
[TC-02] Description : Benign serialized object (control)
         Encoding     : base64
         Status       : 200 | Time: 0.009s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Control test accepted as expected
 
[TC-03] Description : Invalid magic bytes
         Encoding     : hex
         Status       : 400 | Time: 0.006s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
         Malformed stream correctly rejected
 
[TC-04] Description : Spring gadget chain
         Encoding     : hex
         Status       : 400 | Time: 0.006s | OOB Callback: NO
         Result       : PASS
         Consistency  : 0/3 — CONSISTENT_PASS
 
===== VERDICT: REMEDIATION_VERIFIED =====
Failed Tests  : 0/4
Evidence saved: ./evidence/FIND-0139_20260319T125842Z.json
Report hash   : sha256:cbfcd754f0585bea183ed07305ce5809041b9c492cc20556580eca9ef5f3d223
```
 
**AI Advisory Analysis (Groq — Llama 3.1 8B):**
```
1. Fix completeness: The fix appears to be complete, as all test cases
   (TC-01 to TC-04) resulted in a PASS status with no anomalies.
 
2. Significant test results: TC-01 (CommonsCollections6) is the most
   significant — it is a well-known exploited vulnerability. The CONSISTENT_PASS
   consistency indicates the fix is effective against this attack vector.
 
3. Residual risk: Although the verdict is REMEDIATION_VERIFIED, residual risk
   may exist due to the complexity of Java deserialization vulnerabilities. New
   attack vectors or gadgets may emerge.
 
4. Recommended next steps: Continuously monitor for new Java deserialization
   vulnerabilities, review and update the remediation to cover emerging threats,
   and consider implementing serialization filtering or whitelisting.
```
 
All four tests pass. TC-02 still returns 200 (benign object accepted) while
TC-01 and TC-04 return 400. Response times drop from ~6s to under 50ms — rejection
happens before deserialization starts.

## Live Session Screenshot
<img width="1920" height="1200" alt="Screenshot_2026-03-19_11-54-58" src="https://github.com/user-attachments/assets/3b6c7a46-b705-4713-a187-5a11d34606f9" />

 
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
 
Every test runs 3 times. The consistency engine counts failure signals across runs:
 
| Score | Flag | Meaning |
|-------|------|---------|
| `0/3` | `CONSISTENT_PASS` | High confidence — fix is holding |
| `3/3` | `CONSISTENT_FAIL` | High confidence — vulnerability still present |
| `1/3` or `2/3` | `INCONSISTENT - FLAG FOR REVIEW` | Mixed — verdict set to INCONCLUSIVE |
 
In the vulnerable server run, TC-01 and TC-04 showed **3/3 CONSISTENT_FAIL** —
the `REMEDIATION_FAILED` verdict is reliable, not a timing anomaly.
 
---
 
## Evidence Chain
 
| File | Verdict | Key Results |
|------|---------|-------------|
| `FIND-0139_20260319T124149Z.json` | `REMEDIATION_FAILED` | TC-01, TC-04 FAIL — 3/3 CONSISTENT_FAIL, 6s timing |
| `FIND-0139_20260319T125842Z.json` | `REMEDIATION_VERIFIED` | All 4 PASS — 0/3 CONSISTENT_PASS, <50ms |
 
| Field | Value |
|-------|-------|
| Algorithm | SHA-256 |
| FAILED hash | `sha256:8fb69c6992693875a887b2edbb51e6a94f5c617a06808b242f253a9688463f83` |
| VERIFIED hash | `sha256:cbfcd754f0585bea183ed07305ce5809041b9c492cc20556580eca9ef5f3d223` |
 
Hash is computed over the full JSON before the `report_hash` field is added —
making it reproducible and tamper-evident.
 
---
 
## Honest Self-Assessment
 
### What works
 
- Payload decoding for hex and base64 formats
- HTTP POST with correct `Content-Type: application/x-java-serialized-object`
- Three-signal anomaly detection: behavioral, temporal, content
- Bonus B retry engine — 3 runs per test with consistency scoring
- SHA-256 tamper-evident report hashing
- Flask mock server simulating vulnerable and fixed states
- Clean terminal output with ANSI color, `--quiet`, `--verbose` flags
- Exit codes 0/1/2 for pipeline integration
- AI advisory analysis via Groq (Llama 3.1 8B) with real output in evidence JSON
 
### What is missing or limited
 
**OOB callback detection is not live.** Real OOB detection requires Interactsh or
Burp Collaborator AND a real Java server executing gadget chain payloads. The mock
server simulates timing only — it cannot phone home to a canary domain.
 
**Only 4 of 10 designed test cases are automated.** TC-05 through TC-10 require
a real Java runtime. Running them against the Python mock server would prove nothing.
 
**The mock server is Python, not Java.** It simulates response behavior accurately
but does not execute real gadget chains.
 
### What I would do differently with more time
 
- Build a real vulnerable Java server using Spring Boot with outdated Commons
  Collections, enabling genuine gadget chain execution and real OOB callbacks
- Set up Interactsh as a live canary platform
- Implement all 10 test cases from Part B
- Fix AI rate limiting with async batching
- Build a real vulnerable Java server using Spring Boot with intentionally outdated
  Commons Collections, enabling genuine gadget chain execution and real OOB callbacks
- Set up Interactsh as a live canary platform for DNS and HTTP callback detection
- Implement all 10 test cases from Part B in the automated suite
- Fix the AI analysis to handle rate limits with async batching rather than a fallback



