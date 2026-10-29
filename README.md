# AWS Cloud-Native SIEM Framework

> A fully serverless Security Information and Event Management (SIEM) system
> built entirely on AWS-native services — zero third-party tools, zero licensing
> costs, deployable within AWS Free Tier.

![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)
![Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=flat&logo=awslambda&logoColor=white)
![DynamoDB](https://img.shields.io/badge/DynamoDB-4053D6?style=flat&logo=amazondynamodb&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Publication

This repository accompanies the author's BCS Level 6 Professional Graduate Diploma in IT project:

> Alla, O. (2026). *Design and Implementation of an Intelligent Cloud Security Monitoring and Automated Response Framework on AWS*. Zenodo. https://doi.org/10.5281/zenodo.22297638

The full report (literature review, requirements, design, implementation, testing and evaluation) is on Zenodo under CC BY 4.0. ORCID: https://orcid.org/0009-0004-7702-5086. The project was assessed by BCS, The Chartered Institute for IT; publication here is the author's own and does not imply BCS endorsement.

---

## The Problem This Solves

Commercial SIEM platforms (Splunk, Microsoft Sentinel, IBM QRadar) cost
tens of thousands of dollars per year in licensing. This puts enterprise-grade
security monitoring out of reach for small-to-medium enterprises running
cloud-native workloads on AWS.

This project demonstrates that a fully functional SIEM — with real-time threat
detection, automated alerting, and a live dashboard — can be built for **£0**
using only AWS-native serverless services, all within the AWS Free Tier.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOG SOURCES                              │
│  CloudTrail ──┐                                                 │
│  GuardDuty  ──┤──► S3 Bucket (your-siem-logs-bucket)           │
│  VPC Flows  ──┘                                                 │
│  CloudWatch ──────────────────────────────────────────────────┐ │
└───────────────────────────────────────────────────────────────┼─┘
                                                                │
                    ┌───────────────────────────────────────────▼──┐
                    │         AWS Lambda                            │
                    │    siem-correlation-engine (Python 3.12)      │
                    │                                               │
                    │  evaluate_rules() → determine_severity()      │
                    │       ↓                    ↓                  │
                    │  store_event()        send_alert()            │
                    └──────────┬─────────────────┬─────────────────┘
                               │                 │
                    ┌──────────▼──────┐  ┌───────▼────────┐
                    │    DynamoDB     │  │   Amazon SNS   │
                    │  siem-events    │  │  siem-alerts   │
                    │  (audit store)  │  │ (email alerts) │
                    └──────────┬──────┘  └────────────────┘
                               │
                    ┌──────────▼──────┐
                    │  S3 Dashboard   │
                    │  index.html     │
                    │  (static site)  │
                    └─────────────────┘
```

---

## Features

- **10 correlation rules** covering IAM escalation, CloudTrail tampering,
  GuardDuty findings, root account activity, S3 exposure, and more
- **Weighted threat scoring** (0–100) with three severity tiers:
  LOW (0–39), MEDIUM (40–69), HIGH (70–100)
- **Automated SNS email alerts** for MEDIUM and HIGH severity events,
  including triggered rules, source IP, and recommended action
- **DynamoDB audit trail** — every event stored with full forensic detail
  including raw payload, triggered rules, and UUID event ID
- **Real-time security dashboard** — hosted on S3, showing threat score
  distribution, severity breakdown donut chart, and full event log
- **MITRE ATT&CK aligned** — all rules mapped to ATT&CK cloud techniques
- **Sub-second detection** — Lambda execution 314–537ms across all tests
- **Free Tier compatible** — entire stack runs within AWS Free Tier limits

---

## Correlation Rules

| Rule | Event / Condition | Weight | ATT&CK Technique |
|------|-------------------|--------|-----------------|
| R-01 | Root account activity | 30 | T1078.004 |
| R-02 | IAM policy modification | 25 | T1098 |
| R-03 | GuardDuty HIGH (≥7.0) | 40 | Multiple |
| R-04 | GuardDuty MEDIUM (4.0–6.9) | 20 | Multiple |
| R-05 | AccessDenied error | 15 | T1110 |
| R-06 | S3 bucket ACL modification | 35 | T1530 |
| R-07 | Security group ingress added | 20 | T1562.007 |
| R-08 | StopLogging / DeleteTrail | 45 | T1562.008 |
| R-09 | CreateUser | 10 | T1136.003 |
| R-10 | CreateAccessKey (Root) | 30 | T1098.001 |

---

## Test Results

Three attack scenarios were simulated and validated end-to-end:

| Scenario | Event | Score | Severity | SNS Alert | DynamoDB |
|----------|-------|-------|----------|-----------|----------|
| IAM Privilege Escalation | AttachUserPolicy | 25 | LOW | — | ✅ |
| CloudTrail Tampering | StopLogging (IAM user) | 45 | MEDIUM | ✅ Email | ✅ |
| Root + Audit Evasion | StopLogging (Root) | 75 | HIGH | ✅ Email | ✅ |

**Performance metrics:**
- Detection latency: 314–537ms (target: <60s) ✅
- False positive rate: 0% ✅
- False negative rate: 0% ✅
- AWS cost: $0 (within Free Tier) ✅

---

## Tech Stack

| Layer | Service |
|-------|---------|
| Log collection | CloudTrail, GuardDuty, VPC Flow Logs, CloudWatch |
| Storage | Amazon S3, Amazon DynamoDB |
| Compute | AWS Lambda (Python 3.12) |
| Alerting | Amazon SNS |
| Dashboard | S3 Static Website Hosting (HTML5/CSS3/JS) |
| IAM | Custom execution role with scoped policies |

---

## Project Structure

```
aws-cloud-native-siem/
├── lambda/
│   └── correlation_engine/
│       └── lambda_function.py    # Core correlation engine — 10 rules
├── infrastructure/
│   ├── s3-bucket-policy.json    # Bucket policy (CloudTrail + public dashboard)
│   └── iam-role-policy-summary.md
├── tests/
│   ├── scenario-1-iam-escalation.json       # Score 25, LOW
│   ├── scenario-2-cloudtrail-tampering.json  # Score 45, MEDIUM
│   └── scenario-3-root-high.json            # Score 75, HIGH
├── DECISIONS.md                 # Architecture decision log (10 decisions)
└── README.md                    # This file
```

---

## Deployment Guide

### Prerequisites
- AWS account (Free Tier eligible)
- AWS CLI configured with appropriate credentials
- Python 3.12

### Step 1 — Create S3 Bucket
```bash
aws s3 mb s3://your-siem-logs-bucket --region us-east-2
```
Apply the bucket policy from `infrastructure/s3-bucket-policy.json`
(update bucket name to match yours).

### Step 2 — Create DynamoDB Table
```bash
aws dynamodb create-table \
  --table-name siem-events \
  --attribute-definitions \
    AttributeName=event_id,AttributeType=S \
    AttributeName=timestamp,AttributeType=S \
  --key-schema \
    AttributeName=event_id,KeyType=HASH \
    AttributeName=timestamp,KeyType=RANGE \
  --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
  --region us-east-2
```

### Step 3 — Create SNS Topic
```bash
aws sns create-topic --name siem-alerts --region us-east-2
# Subscribe your email:
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-2:YOUR_ACCOUNT_ID:siem-alerts \
  --protocol email \
  --notification-endpoint your@email.com \
  --region us-east-2
```

### Step 4 — Create IAM Role
Create role `siem-lambda-execution-role` with Lambda trust policy.
Attach: `AmazonDynamoDBFullAccess`, `AmazonSNSFullAccess`, `CloudWatchFullAccess`.

### Step 5 — Deploy Lambda Function
```bash
cd lambda/correlation_engine
# Update SNS_TOPIC_ARN and REGION in lambda_function.py first
zip function.zip lambda_function.py
aws lambda create-function \
  --function-name siem-correlation-engine \
  --runtime python3.12 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/siem-lambda-execution-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --region us-east-2
```

### Step 6 — Enable Log Sources
- **CloudTrail:** Create multi-region trail → S3 destination → your bucket
- **GuardDuty:** Enable in console (30-day free trial)
- **VPC Flow Logs:** VPC console → Your VPCs → Actions → Create flow log → S3

### Step 7 — Deploy Dashboard
The static dashboard (`dashboard/index.html`) is described in the published report and is not included in this repository. Build your own from the DynamoDB records, then:
```bash
aws s3 cp dashboard/index.html s3://your-siem-logs-bucket/index.html
```
Enable static website hosting on the bucket.

### Step 8 — Run a Test
```bash
aws lambda invoke \
  --function-name siem-correlation-engine \
  --payload file://tests/scenario-3-root-high.json \
  --cli-binary-format raw-in-base64-out \
  --region us-east-2 \
  response.json && cat response.json
```
Expected output: `{"threat_score": 75, "severity": "HIGH", "rules_triggered": 2}`

---

## Planned Enhancements

- [ ] API Gateway → Lambda → DynamoDB for live dashboard data
- [ ] CloudFront + ACM for HTTPS dashboard
- [ ] AWS Step Functions automated response orchestration
- [ ] SageMaker ML anomaly detection layer
- [ ] MITRE ATT&CK tactic display on dashboard
- [ ] Multi-region deployment (us-east-1, eu-west-1)
- [ ] Slack/Teams SNS notification endpoint
- [ ] Terraform IaC for reproducible deployment
- [ ] GitHub Actions CI/CD for rule updates
- [ ] Expand rule set from 10 to 20+ rules

---

## Background

This project was developed as the author's BCS Higher Education Qualifications
Professional Graduate Diploma in IT project (submitted March 2026, diploma
awarded April 2026). The code is published here as an open-source reference
architecture for cloud-native security monitoring on AWS; the full written
report is on Zenodo (see Publication above).

---

## Author

**Femi Alla** — Cloud DevOps Engineer
- GitHub: [@femi-alla](https://github.com/femi-alla)
- ORCID: [0009-0004-7702-5086](https://orcid.org/0009-0004-7702-5086)

---

## Licence

MIT Licence — see [LICENSE](LICENSE) for details.

Free to use, adapt, and build upon with attribution.
