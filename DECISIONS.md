# DECISIONS.md — Architecture Decision Log
# aws-cloud-native-siem | Femi Alla

This file records every significant architectural and technical decision made
during the project. Each entry explains what was decided, why, and what the
alternatives were. This is the source of truth for "why did we do it this way?"

---

## D-01: Event Storage — DynamoDB over OpenSearch

**Decision:** Use Amazon DynamoDB as the event store.
**Alternatives considered:** Amazon OpenSearch Service, Amazon RDS PostgreSQL
**Date decided:** February 2026

**Rationale:**
- OpenSearch requires cluster management, index mapping, and domain configuration
  — significant operational overhead for a prototype
- OpenSearch costs exceed Free Tier limits for always-on clusters
- DynamoDB's key-value model is sufficient for the storage/retrieval patterns
  required (store by event_id, scan for dashboard)
- DynamoDB Free Tier (25GB, 25 RCU/WCU) comfortably covers test volume
- RDS requires VPC subnet group, security group, and connection management —
  disproportionate complexity for this use case

**Future:** For production scale (thousands of events/hour), migrate to
Amazon OpenSearch Serverless for full-text search and Kibana integration.

---

## D-02: Compute — Serverless Lambda over EC2/ECS

**Decision:** Use AWS Lambda for all compute.
**Alternatives considered:** EC2 instance running Python, ECS Fargate container
**Date decided:** February 2026

**Rationale:**
- Lambda requires zero infrastructure management
- Pay-per-invocation pricing — Free Tier covers 1M invocations/month
- Event-driven model aligns naturally with security event processing
- Cold start latency (529ms observed) is acceptable for security alerting
  where 60-second detection SLA is the target
- EC2/ECS would require always-on compute, significantly increasing cost

---

## D-03: Deployment Method — Manual Console over Terraform

**Decision:** Deploy all infrastructure manually via AWS Management Console.
**Alternatives considered:** Terraform, AWS CloudFormation, AWS CDK
**Date decided:** February 2026

**Rationale:**
- Prototype-stage deployment benefits from visual feedback and iterative
  troubleshooting — especially useful when debugging IAM permission errors
- Terraform adds IaC learning curve that would consume project time
- Console deployment enabled faster iteration and immediate error visibility

**Acknowledged limitation:** Console deployment is not reproducible.
**Future:** Migrate all resources to Terraform as Enhancement #9 (see Planned Enhancements in README).

---

## D-04: Dashboard Technology — Vanilla HTML/JS over React/Vue

**Decision:** Build dashboard as single-file vanilla HTML5/CSS3/JavaScript.
**Alternatives considered:** React + Recharts, Vue.js + Chart.js
**Date decided:** February 2026

**Rationale:**
- Single file deploys directly to S3 with no build tooling
- No npm, no webpack, no dependency management
- No framework overhead for a prototype with ~4 events
- Fully self-contained — works offline from the file system for demos
- Google Fonts loaded via CDN — only external dependency

**Acknowledged limitation:** Event data is embedded at build time.
**Future:** Connect to API Gateway → Lambda → DynamoDB for live data (Enhancement #1).

---

## D-05: Alert Delivery — SNS Email over Slack/PagerDuty

**Decision:** Use Amazon SNS with email subscription for alert delivery.
**Alternatives considered:** Slack Incoming Webhooks, PagerDuty, SMS
**Date decided:** February 2026

**Rationale:**
- SNS email subscription is Free Tier and requires no third-party integration
- Confirmed subscription provides verifiable audit evidence for BCS report
- Email format allows rich plain-text alert content including all rule details
- Slack/PagerDuty integration requires webhook URL management and API keys

**Future:** Add Slack endpoint as second SNS subscription (Enhancement #8).

---

## D-06: Lambda Runtime — Python 3.12 over Node.js/Go

**Decision:** Use Python 3.12 as Lambda runtime.
**Alternatives considered:** Node.js 20, Go 1.21
**Date decided:** February 2026

**Rationale:**
- boto3 AWS SDK for Python is the most mature and well-documented AWS SDK
- Python's json, uuid, datetime standard library modules cover all requirements
  with zero additional dependencies
- Python is the dominant language in cloud security tooling and scripting
- Personal proficiency — fastest development velocity

---

## D-07: Step Functions — Descoped to Direct SNS in Lambda

**Decision:** Implement SNS notification directly in Lambda rather than via
Step Functions state machine.
**Date decided:** March 2026 (during implementation)

**Rationale:**
- Time constraints — Step Functions ASL design and testing would consume
  approximately one additional day
- Direct SNS call from Lambda provides equivalent alert delivery for the
  prototype's requirements
- State machine complexity (parallel branches, error handling, retry logic)
  is only justified at production scale

**ASL definition preserved in:** `infrastructure/step-functions-asl.json`
**Future:** Implement full state machine as Enhancement #2 (see Planned Enhancements in README).

---

## D-08: Scoring Thresholds — Empirical over Statistical

**Decision:** Set MEDIUM threshold at 40, HIGH threshold at 70.
**Date decided:** February 2026

**Rationale:**
- No labelled dataset of real cloud security events available for statistical
  optimisation
- Thresholds designed so that:
  - Single low-risk events (CreateUser, AccessDenied) remain LOW
  - Single medium-risk events (StopLogging alone at 45) trigger MEDIUM
  - Combinations of high-risk events (Root + StopLogging = 75) trigger HIGH
- Validated through three test scenarios with 0% false positive / 0% false
  negative rate on tested event types

**Future:** Collect real event data and use ROC curve analysis to optimise
thresholds for minimum combined false positive + false negative rate.

---

## D-09: Dashboard Hosting — S3 Static Website over CloudFront

**Decision:** Host dashboard on S3 static website hosting (HTTP only).
**Alternatives considered:** CloudFront + ACM (HTTPS), Amplify Hosting
**Date decided:** March 2026

**Rationale:**
- S3 static hosting is sufficient for prototype demonstration
- CloudFront setup requires certificate validation and distribution
  configuration — 30–45 minutes of additional work with deadline pressure
- Amplify adds deployment pipeline complexity not needed for a single HTML file

**Acknowledged limitation:** Dashboard served over HTTP, not HTTPS.
**Future:** Add CloudFront distribution with ACM certificate (Enhancement #2).

---

## D-10: Region — us-east-2 (Ohio) as Primary Region

**Decision:** Deploy all resources in us-east-2.
**Alternatives considered:** us-east-1 (N. Virginia)
**Date decided:** February 2026

**Rationale:**
- us-east-2 is less congested than us-east-1 — lower API throttling risk
- Consistent region selection prevents cross-region data transfer costs
- Note: Lambda was accidentally first deployed to us-east-1 and redeployed
  to us-east-2 — this is documented as an implementation challenge in the
  BCS project report Section 5.4.2

---

## Implementation Challenges Log

| Challenge | Root Cause | Resolution |
|---|---|---|
| IAM user insufficient permissions | mybcsproject lacked CloudTrail/CloudShell rights | Root account attached AdministratorAccess |
| Lambda deployed to wrong region | Console defaulted to us-east-1 | Deleted us-east-1 function, redeployed in us-east-2 |
| DynamoDB AccessDeniedException on first test | AmazonDynamoDBFullAccess not attached to role | Added policy via IAM console |
| Test event name too long (>25 chars) | AWS Lambda console 25-char limit on event names | Shortened to test-iam-escalation |
| R-01 not triggering on Root+StopLogging | Rule checked ConsoleLogin/GetSessionToken only | Updated to fire on any Root user_type |
| S3 dashboard 403 Forbidden | bucket owner enforced — ACL approach blocked | Added PublicReadDashboard bucket policy statement |
