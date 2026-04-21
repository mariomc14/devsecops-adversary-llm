# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7, 2.2
- **Evaluation Date**: 2026-04-21

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-21 10:59:09,927 [INFO]   HttpTokens=required  HopLimit=1  Endpoint=enabled  State=applied
2026-04-21 10:59:11,066 [INFO]   Step 1.7 DENIED (UnauthorizedOperation) – preventive control held.
2026-04-21 10:59:17,032 [INFO]   SSM status=Success stdout=TOKEN_HTTP=200 V1_HTTP=401
2026-04-21 10:59:17,033 [INFO]   IMDSv1 GET returned 401 – blocked by IMDSv2.
2026-04-21 10:59:17,036 [INFO]   Step 1.2: {'success': True, 'tokens': 'required', 'hop': 1}
2026-04-21 10:59:17,036 [INFO]   Step 1.7: {'success': False, 'blocked': True, 'code': 'UnauthorizedOperation'}
2026-04-21 10:59:17,037 [INFO]   Step 2.2: {'success': False, 'blocked': True, 'detail': 'imdsv2_401', 'stdout': 'TOKEN_HTTP=200 V1_HTTP=401'}
```

**Justification**: All three attack steps were executed with verifiable evidence:
- **Attack 1.2 (T1580 - Cloud Infrastructure Discovery)**: Successfully enumerated the IMDS configuration, confirming `HttpTokens=required` and `HopLimit=1`. The enumeration returned concrete, verifiable metadata attributes.
- **Attack 1.7 (T1562.001 - Impair Defenses)**: The attacker role attempted to modify the instance metadata options (IMDS downgrade). The API call was made and a specific `UnauthorizedOperation` error code was returned, proving the attack was actually attempted against real AWS infrastructure.
- **Attack 2.2 (T1552.005 - Unsecured Credentials via IMDS)**: An SSM command was sent to the instance (command ID `774a121d-7b1b-45ed-ab19-83e19fcb41b0`), which executed and returned concrete HTTP status codes (`TOKEN_HTTP=200 V1_HTTP=401`). The IMDSv2 token request succeeded (200) while the IMDSv1 credential request was rejected (401), demonstrating that a real credential exfiltration attempt was made.

All actions produced concrete, non-fabricated evidence (AWS error codes, HTTP status codes, SSM command IDs, instance IDs) confirming real execution.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-21 10:59:17,055 [INFO] Check 1 – Enumeration (1.2): success=True
2026-04-21 10:59:17,057 [INFO]   ✓ IMDS config confirmed: tokens=required, hop=1
2026-04-21 10:59:17,058 [INFO] Check 2 – IMDS Modify (1.7): blocked=True
2026-04-21 10:59:17,059 [INFO]   ✓ Preventive control blocked IMDS downgrade (code=UnauthorizedOperation)
2026-04-21 10:59:17,060 [INFO] Check 3 – Credential Exfiltration (2.2): blocked=True detail=imdsv2_401
2026-04-21 10:59:17,061 [INFO]   ✓ Credential exfiltration prevented
2026-04-21 10:59:17,740 [INFO]   ✓ IMDS still enforced: tokens=required hop=1
2026-04-21 10:59:17,740 [INFO] RESULT: PASSED  (4/4 checks passed)
```

**Justification**: The probe (steady-state hypothesis verification) performed a comprehensive 4-check validation with verifiable results:
1. **Check 1**: Verified that IMDS enumeration returned the expected secure configuration (`tokens=required`, `hop=1`), confirming the baseline defense posture.
2. **Check 2**: Verified that the IAM-based preventive control blocked the IMDS downgrade attempt, with the specific denial code (`UnauthorizedOperation`) serving as evidence.
3. **Check 3**: Verified that credential exfiltration was prevented, with the `imdsv2_401` detail confirming that IMDSv2 enforcement blocked the IMDSv1 credential retrieval path.
4. **Final Check**: Re-confirmed the IMDS configuration was unchanged post-attack (`tokens=required hop=1`), verifying defense integrity was maintained throughout the experiment.

The probe returned a clear, binary, verifiable verdict: `PASSED (4/4 checks passed)` with the steady-state hypothesis met. Each check maps directly to a specific defense behavior (IAM deny policy, IMDSv2 enforcement, hop limit) and provides concrete evidence of that behavior.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: 80
**Result**: Q_post >= 80

## DECISION

**VALID EXECUTION**

---

## Recommendations

While the experiment execution is fully valid and high quality, minor improvements could be considered for future iterations:

1. **Timing instrumentation**: Adding per-step latency measurements would help characterize defense response times (e.g., how quickly IAM denies the modify-instance-metadata-options call).
2. **CloudTrail correlation**: Capturing CloudTrail event IDs for the denied API calls would provide an additional layer of forensic evidence and could feed into detective control validation.
3. **Expanded hop limit testing**: Consider adding a test from a container or secondary network hop to validate that `HopLimit=1` effectively prevents IMDS access from non-instance contexts (e.g., Docker containers on the host).
4. **Negative control**: Running the same experiment on an instance without IMDSv2 enforcement (in an isolated environment) would strengthen the causal claim that the controls are what prevented the attacks.