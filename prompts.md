# prompts.md — Part C: AI-Assisted Workflow

## What Part C asks for

Part C requires using an AI tool to generate a Python function that:
- Takes a target API endpoint and a list of pre-generated serialized payloads
- Sends each with the correct Content-Type header
- Detects whether deserialization was triggered via OOB DNS/HTTP callback

This documents the exact prompt used, the raw AI output, our critique of it,
and the corrected version we actually used.

---

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
