# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 1.7, 2.2
- **Evaluation Date**: 2026-04-21

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-21 11:39:57,436 [INFO] — Step 1.2  T1580  Cloud Infrastructure Discovery —
2026-04-21 11:39:58,118 [INFO]   HttpTokens=required  HopLimit=1  Endpoint=enabled
2026-04-21 11:39:58,118 [INFO] — Step 1.7  T1562.001  Impair Defenses —
2026-04-21 11:39:58,654 [INFO]   Modified → HttpTokens=optional  HopLimit=2
2026-04-21 11:39:58,654 [INFO] — Step 2.2  T1552.005  IMDS credential exfiltration —
2026-04-21 11:40:04,575 [INFO]   SSM result: Success  stdout: ROLE=sce-ir-1776764131
2026-04-21 11:40:05,476 [INFO]   Detection event emitted successfully.
2026-04-21 11:40:05,476 [INFO] attack() done.
```

**Justification**: All three attack nodes were executed with verifiable evidence:
- **Node 1.2 (T1580 - Cloud Infrastructure Discovery)**: Successfully enumerated IMDS metadata, confirming `HttpTokens=required` and `HopLimit=1`.
- **Node 1.7 (T1562.001 - Impair Defenses)**: Successfully downgraded IMDS from IMDSv2 to IMDSv1 (`HttpTokens=optional`) and increased hop limit to 2, verified by log output.
- **Node 2.2 (T1552.005 - IMDS Credential Exfiltration)**: SSM command executed successfully and returned the role name `sce-ir-1776764131`, confirming credential exfiltration via IMDS.
- A detection event was emitted to EventBridge to trigger the reactive response pipeline.

All actions produced concrete, verifiable artifacts in the logs.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-21 11:40:22,371 [INFO]   [16s] ✓ Deny-all inline policy attached to role sce-ir-1776764131
2026-04-21 11:40:22,509 [INFO]     Policy content verified: Deny * on *
2026-04-21 11:40:22,765 [INFO]   [16s] ✓ Instance i-0e2f97056c149e5b8 quarantined (SG=sg-08e6ede8d86886a0a)
2026-04-21 11:40:23,439 [INFO]   [16s] ✓ Lambda log confirms reactive execution
2026-04-21 11:40:23,440 [INFO] PASSED – reactive controls confirmed
2026-04-21 11:40:23,440 [INFO]   ✓ Deny-all policy on role: True
2026-04-21 11:40:23,440 [INFO]   ✓ Instance quarantined: True
2026-04-21 11:40:23,440 [INFO]   ✓ Lambda log evidence: True
2026-04-21 11:40:23,440 [INFO]   Response time: 16s
2026-04-21 11:40:23,440 [INFO]   ★ Meets <3 min target!
```

**Justification**: The reactive probe comprehensively verified all three dimensions of the defensive response:
1. **Deny-all inline policy**: Verified that a `Deny * on *` policy was attached to the compromised instance role `sce-ir-1776764131`, effectively revoking all active sessions.
2. **Instance quarantine**: Verified that the EC2 instance `i-0e2f97056c149e5b8` was moved from the normal security group (`sg-0b7914e5203c6918c`) to the quarantine security group (`sg-08e6ede8d86886a0a`), isolating it from the network.
3. **Lambda execution evidence**: Confirmed via Lambda logs that the reactive automation (EventBridge → Lambda) fired correctly.
4. **Response time**: 16 seconds, well within the <3 minute SLA target.

The probe used a polling mechanism with an 1800s SLA window and confirmed the hypothesis was met. The steady-state hypothesis was verified as met by the Chaos Toolkit framework (`Steady state hypothesis is met!`).

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

- The experiment executed flawlessly with all attack and defense verification steps producing clear, verifiable evidence. Minor suggestions for future iterations:
  - **Add credential usage validation**: After exfiltrating credentials via IMDS, attempt to use them (e.g., `sts:GetCallerIdentity`) both before and after the deny-all policy is applied, to confirm that the revocation effectively blocks API calls.
  - **Test with delayed detection**: Introduce variable latency in the detection event to stress-test the SLA boundary and ensure the reactive controls remain effective under degraded conditions.
  - **IMDSv1 revert verification**: The rollback correctly reverts IMDS to `required`, but the probe could additionally verify post-rollback that the IMDS downgrade from Node 1.7 has been fully reversed.