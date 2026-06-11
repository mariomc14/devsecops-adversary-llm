# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-04 21:34:32 (based on experiment completion)

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-04 21:34:08,705 [INFO] === ATTACK === Attempting to create a malicious CodeBuild project
2026-04-04 21:34:09,192 [INFO] Successfully assumed attack role
2026-04-04 21:34:09,687 [INFO] CreateProject denied: AccessDeniedException — User: arn:aws:sts::941377112071:assumed-role/sce-attack-role-1775356390/sce-attack-session-1775356390 is not authorized to perform: codebuild:CreateProject on resource: arn:aws:codebuild:us-east-1:941377112071:project/sce-malicious-project-1775356390 with an explicit deny in an identity-based policy
2026-04-04 21:34:09,687 [INFO] Attack evidence collected: {"outcome": "access_denied", "error_code": "AccessDeniedException", ...}
```
**Justification**: The ACTION executed completely and returned verifiable evidence. The attack role was successfully assumed, and an actual `codebuild:CreateProject` API call was made against the real AWS environment. The response was captured with full details including the error code (`AccessDeniedException`), the specific ARN of the denied resource, the identity-based policy that caused the denial, and the HTTP status code (400). The evidence is structured as a JSON object with outcome, error code, error message, and HTTP status — all verifiable artifacts of real execution.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-04 21:34:09,690 [INFO] === HYPOTHESIS VERIFICATION === Checking preventive control effectiveness
2026-04-04 21:34:09,690 [INFO] CHECK 1 PASSED: Attack was denied with AccessDeniedException
2026-04-04 21:34:10,095 [INFO] CHECK 2 PASSED: Project sce-malicious-project-1775356390 does not exist
2026-04-04 21:34:10,618 [INFO] CHECK 3 PASSED: Deny policy 'sce-deny-codebuild-create-1775356390' is attached to role
2026-04-04 21:34:10,618 [INFO] === HYPOTHESIS VERIFIED: Preventive control successfully blocked malicious CodeBuild project creation ===
[2026-04-04 21:34:10 INFO] Steady state hypothesis is met!
```
**Justification**: The PROBE performed three distinct, verifiable checks that comprehensively validate the preventive control's behavior:
1. **Check 1**: Verified the API call was denied with the expected `AccessDeniedException` error code — confirming the deny policy intercepted the request.
2. **Check 2**: Verified that the malicious CodeBuild project (`sce-malicious-project-1775356390`) does not exist in the account — confirming no resource was actually created (the deny was effective, not just a logged warning).
3. **Check 3**: Verified that the deny policy (`sce-deny-codebuild-create-1775356390`) is actually attached to the role — confirming the preventive control mechanism is properly configured.

All three checks passed with clear timestamps showing real API calls (note the time deltas between checks indicating actual AWS API queries). The hypothesis was verified as met, providing verifiable evidence of the defense behavior.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**
Q_post = 100.00

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment execution is exemplary. A few minor suggestions for further enhancement:

1. **CloudTrail Correlation**: Consider adding a fourth check that queries CloudTrail for the denied `CreateProject` event to provide an independent audit trail verification beyond the API response.
2. **Negative Control**: Consider an optional step that temporarily removes the deny policy and confirms the `CreateProject` call would succeed (then re-applies the policy), to ensure the test isn't passing due to some other access restriction.
3. **SCP Testing**: If this environment uses AWS Organizations, consider testing whether Service Control Policies (SCPs) provide a layered defense in addition to the identity-based deny policy.