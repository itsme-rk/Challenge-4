# remcheck v0.1.0

Automated remediation verification tool for security findings.
Submission for Challenge 4 (Insecure Java Deserialization) + Default Challenge.

## Installation
```bash
git clone https://github.com/YOURUSERNAME/remcheck.git
cd remcheck
pip3 install flask requests
```

## Usage

### Step 1 — Start the mock server
```bash
# Simulate unpatched vulnerable server
python3 src/mock_server.py --mode vulnerable

# Simulate patched/fixed server
python3 src/mock_server.py --mode fixed
```

### Step 2 — Run the verifier
```bash
# Basic run
python3 src/verify_deserial.py \
  --finding finding_examples/deserial_example.json \
  --output ./evidence

# Quiet mode
python3 src/verify_deserial.py \
  --finding finding_examples/deserial_example.json --quiet

# Verbose mode
python3 src/verify_deserial.py \
  --finding finding_examples/deserial_example.json --verbose

# With AI analysis
export GROQ_API_KEY="your-key"
python3 src/verify_deserial.py \
  --finding finding_examples/deserial_example.json
```

## End-to-end example

### Vulnerable server output
```
===== REMEDIATION VERIFICATION REPORT =====
Finding   : FIND-0139 (insecure_deserialization)
Target    : http://127.0.0.1:5000/post

[TC-01] CommonsCollections6 gadget chain
        Status: 200 | Time: 6.013s | Result: FAIL
        [ANOMALY] BEHAVIORAL + TEMPORAL
        Consistency: 3/3 CONSISTENT_FAIL

[TC-04] Spring gadget chain
        Status: 200 | Time: 6.008s | Result: FAIL
        Consistency: 3/3 CONSISTENT_FAIL

===== VERDICT: REMEDIATION_FAILED =====
```

### Fixed server output
```
[TC-01] Status: 400 | Time: 0.012s | Result: PASS
[TC-02] Status: 200 | Time: 0.008s | Result: PASS
[TC-03] Status: 400 | Time: 0.004s | Result: PASS
[TC-04] Status: 400 | Time: 0.007s | Result: PASS

===== VERDICT: REMEDIATION_VERIFIED =====
```

## Exit codes
| Code | Meaning |
|------|---------|
| 0 | REMEDIATION_VERIFIED |
| 1 | REMEDIATION_FAILED |
| 2 | INCONCLUSIVE |

## Design decisions
1. Python Flask mock server used instead of real Java target to stay within time constraints
2. Groq free tier (Llama 3.1 8B) used for AI analysis layer
3. OOB detection implemented but uses placeholder canary URL

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
└── evidence/    <- gitignored
```
