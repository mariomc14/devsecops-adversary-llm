# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.3, 2.4
- **Evaluation Date**: 2026-04-21

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-21 10:42:52,759 [INFO]   HttpTokens=required  HopLimit=1  Endpoint=enabled  State=applied
2026-04-21 10:42:53,302 [INFO]   Modified → HttpTokens=optional  HopLimit=2
2026-04-21 10:42:56,496 [INFO]   CONFIRMED: IMDS downgraded.
```
**Justification**: Both attack nodes were executed with verifiable evidence:
- **Attack Node 1.3 (T1580 - Cloud Infrastructure Discovery)**: The experiment successfully enumerated the EC2 instance's IMDS configuration, confirming `HttpTokens=required`, `HopLimit=1`, `Endpoint=enabled`, and `State=applied`. This constitutes a verified reconnaissance step.
- **Attack Node 2.4 (T1562.001 - Impair Defenses)**: The IMDS was successfully downgraded from `required` to `optional` with the hop limit changed from 1 to 2. The downgrade was explicitly confirmed via a follow-up verification (`CONFIRMED: IMDS downgraded`). This is clear, verifiable evidence that the attack action was carried out successfully.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-21 10:44:17,699 [INFO]   [80s] ✓ NON_COMPLIANT detected
2026-04-21 10:44:33,114 [INFO]   [96s] ✓ IMDS reverted
2026-04-21 10:44:33,826 [INFO]   [96s] ✓ Lambda log confirmed
2026-04-21 10:44:33,826 [INFO] PASSED  nc=True reverted=True lambda_log=True  t=96s
2026-04-21 10:44:33,826 [INFO] ★ Meets <5 min target (96s)
```
**Justification**: The reactive probe provided comprehensive, verifiable evidence of the defense behavior:
1. **Detection**: AWS Config detected the NON_COMPLIANT state at 80 seconds after the attack.
2. **Remediation**: The auto-remediation Lambda successfully reverted the IMDS settings back to `required` with hop limit 1, confirmed at 96 seconds.
3. **Lambda log confirmation**: The probe verified that the Lambda function execution was logged, providing an independent audit trail.
4. **SLA compliance**: The entire detection-and-remediation cycle completed in 96 seconds, well within the 1800-second SLA and the 5-minute target.
5. **Polling approach**: The probe used a structured polling mechanism with Config re-evaluation triggers, providing a clear timeline of the reactive control's behavior from detection through remediation.

All three verification criteria (`nc=True`, `reverted=True`, `lambda_log=True`) passed, and the steady-state hypothesis was confirmed met.

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

- **Minor rollback ordering issue**: The log shows a `LastDeliveryChannelDeleteFailedException` because the delivery channel deletion was attempted before stopping the Config recorder. While this was handled gracefully (the recorder was subsequently deleted), the rollback sequence should be reordered to stop/delete the recorder first, then delete the delivery channel.
- **Observability enhancement**: Consider capturing the SNS notification delivery as an additional verification point, since the architecture includes an SNS topic. This would validate the full alerting pipeline alongside the auto-remediation.
- **Drift window analysis**: The 80-second window between attack execution and NON_COMPLIANT detection represents the exposure period. Consider documenting this as a key metric for risk assessment purposes.