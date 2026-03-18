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
