# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.4
- **Probe Type**: Preventive
- **Attack Nodes**: 1.3, 2.3, 3.3
- **Evaluation Date**: 2026-04-17

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-17 11:13:30,333 [INFO] attack: ==================================================
2026-04-17 11:13:30,333 [INFO] attack: ATTACK: SCE 3.4 Preventive
2026-04-17 11:13:30,333 [INFO] attack: ==================================================
2026-04-17 11:13:30,912 [INFO] attack: ------------------------------
2026-04-17 11:13:30,913 [INFO] attack: Step 1.3: Discovery (T1580)
2026-04-17 11:13:31,506 [INFO] attack: Discovery OK: HttpTokens=required, HopLimit=1
2026-04-17 11:13:31,506 [INFO] attack: ------------------------------
2026-04-17 11:13:31,506 [INFO] attack: Step 2.3: Modify IMDS (T1562.001) - EXPECT BLOCKED
2026-04-17 11:13:31,729 [INFO] attack: IMDS modification BLOCKED: UnauthorizedOperation
2026-04-17 11:13:31,729 [INFO] attack: ------------------------------
2026-04-17 11:13:31,729 [INFO] attack: Step 3.3: Verify IMDS (T1552.005)
2026-04-17 11:13:32,388 [INFO] attack: IMDS: HttpTokens=required, HopLimit=1
2026-04-17 11:13:32,395 [INFO] attack: ATTACK COMPLETE
```

**Justification**: The ACTION phase executed all three attack nodes successfully with verifiable evidence:

1. **Node 1.3 (Discovery - T1580)**: Successfully discovered IMDS configuration showing `HttpTokens=required, HopLimit=1`
2. **Node 2.3 (Modify IMDS - T1562.001)**: Attempted to weaken IMDS protection and received expected `UnauthorizedOperation` error - demonstrating the attack was executed and blocked
3. **Node 3.3 (Verify IMDS - T1552.005)**: Verified IMDS settings remained unchanged at `HttpTokens=required, HopLimit=1`

The attack chain was fully executed with clear timestamps, specific AWS resource identifiers (instance ID `i-02b5d1e8a2df09cfa`), and documented outcomes for each step.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-17 11:13:32,453 [INFO] hypothesis_verification: ==================================================
2026-04-17 11:13:32,454 [INFO] hypothesis_verification: VERIFICATION: SCE 3.4 Preventive
2026-04-17 11:13:32,455 [INFO] hypothesis_verification: ==================================================
2026-04-17 11:13:32,456 [INFO] hypothesis_verification: ✓ imds_blocked: True
2026-04-17 11:13:32,456 [INFO] hypothesis_verification: ✓ imdsv2_ok: True
2026-04-17 11:13:32,457 [INFO] hypothesis_verification: ✓ hop_ok: True
2026-04-17 11:13:32,457 [INFO] hypothesis_verification: ==================================================
2026-04-17 11:13:32,458 [INFO] hypothesis_verification: RESULT: PASS
2026-04-17 11:13:32,458 [INFO] hypothesis_verification: ==================================================
[32m[2026-04-17 11:13:32 INFO] Steady state hypothesis is met!
```

**Justification**: The PROBE returned comprehensive verifiable evidence of defense behavior:

1. **`imds_blocked: True`** - Confirmed the preventive control successfully blocked the IMDS modification attempt (UnauthorizedOperation)
2. **`imdsv2_ok: True`** - Verified that IMDSv2 enforcement (`HttpTokens=required`) remained intact
3. **`hop_ok: True`** - Confirmed the hop limit restriction (`HopLimit=1`) was preserved

The steady-state hypothesis "Preventive Controls Block IMDS Protection Weakening" was explicitly validated with a clear PASS result. The probe demonstrated that preventive IAM controls effectively prevented the attacker role from weakening EC2 IMDS protection settings.

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

The experiment executed flawlessly with complete observability. For future iterations, consider:

1. **Enhanced Telemetry**: Add CloudTrail event IDs in the logs to provide forensic traceability of the blocked API calls
2. **Multiple Attack Vectors**: Consider testing additional IMDS weakening methods (e.g., changing `HttpPutResponseHopLimit` independently)
3. **SCP Verification**: Explicitly log which preventive control (IAM policy vs SCP) blocked the modification attempt
4. **Timing Metrics**: Include latency measurements for the prevention mechanism to establish baseline response times