"""
AWS Cloud-Native SIEM — Correlation Engine
==========================================
Author:      Femi Alla
GitHub:      https://github.com/femi-alla/aws-cloud-native-siem
Description: Custom rule-based correlation engine for cloud security event
             processing. Evaluates incoming security events against 10 weighted
             threat rules, computes a composite threat score, persists events
             to DynamoDB, and dispatches SNS alerts for MEDIUM/HIGH severity.

Originally developed as a BCS HEQ PGD in IT Professional Project (2026).
"""

import json
import boto3
import uuid
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────
# Replace these values with your own before deploying
REGION           = "us-east-2"                                    # Your AWS region
SNS_TOPIC_ARN    = "arn:aws:sns:us-east-2:YOUR_ACCOUNT_ID:siem-alerts"  # Your SNS ARN
DYNAMODB_TABLE   = "siem-events"                                  # Your DynamoDB table name
HIGH_THRESHOLD   = 70
MEDIUM_THRESHOLD = 40

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns      = boto3.client("sns",        region_name=REGION)
table    = dynamodb.Table(DYNAMODB_TABLE)


# ── Correlation Rules ───────────────────────────────────────────────────────────
def evaluate_rules(event):
    """
    Evaluate all 10 correlation rules against a normalised security event.

    Args:
        event (dict): Normalised event with 'source' and 'raw_event' keys.

    Returns:
        tuple: (triggered_rules list, total_score int)

    Rule weights are additive. Score is capped at 100.
    Severity thresholds: LOW <40, MEDIUM 40-69, HIGH >=70
    """
    triggered = []
    score     = 0

    raw       = event.get("raw_event", {})
    src       = event.get("source", "")
    evt_name  = raw.get("eventName", "")
    user_type = raw.get("userIdentity", {}).get("type", "")
    error     = raw.get("errorCode", "")
    severity  = float(raw.get("severity", 0))

    # ── R-01: Root account activity ────────────────────────────────────────────
    # Any AWS action performed by the root account user is flagged.
    # Root usage is prohibited under AWS security best practices.
    # MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
    if user_type == "Root":
        triggered.append({
            "rule_id":     "R-01",
            "description": "Root account login detected",
            "weight":      30
        })
        score += 30

    # ── R-02: IAM privilege escalation ─────────────────────────────────────────
    # Policy attachment or modification events indicate potential privilege
    # escalation — a common post-exploitation technique.
    # MITRE ATT&CK: T1098 (Account Manipulation)
    if evt_name in [
        "AttachUserPolicy", "PutUserPolicy",
        "AttachRolePolicy", "PutRolePolicy",
        "CreatePolicyVersion", "SetDefaultPolicyVersion"
    ]:
        triggered.append({
            "rule_id":     "R-02",
            "description": "IAM policy modification detected",
            "weight":      25
        })
        score += 25

    # ── R-03: GuardDuty HIGH severity finding ──────────────────────────────────
    # GuardDuty severity >= 7.0 indicates high-confidence threat detection.
    # MITRE ATT&CK: Multiple techniques depending on finding type
    if src == "guardduty" and severity >= 7.0:
        triggered.append({
            "rule_id":     "R-03",
            "description": "GuardDuty HIGH severity finding",
            "weight":      40
        })
        score += 40

    # ── R-04: GuardDuty MEDIUM severity finding ────────────────────────────────
    # GuardDuty severity 4.0–6.9 indicates medium-confidence threat detection.
    if src == "guardduty" and 4.0 <= severity < 7.0:
        triggered.append({
            "rule_id":     "R-04",
            "description": "GuardDuty MEDIUM severity finding",
            "weight":      20
        })
        score += 20

    # ── R-05: AccessDenied error ───────────────────────────────────────────────
    # Repeated AccessDenied errors indicate reconnaissance or brute-force
    # attempts against AWS resources.
    # MITRE ATT&CK: T1110 (Brute Force)
    if error == "AccessDenied":
        triggered.append({
            "rule_id":     "R-05",
            "description": "AccessDenied error recorded",
            "weight":      15
        })
        score += 15

    # ── R-06: S3 bucket ACL modification ───────────────────────────────────────
    # Bucket ACL changes may indicate data exfiltration preparation
    # (making a bucket public).
    # MITRE ATT&CK: T1530 (Data from Cloud Storage)
    if evt_name == "PutBucketAcl":
        triggered.append({
            "rule_id":     "R-06",
            "description": "S3 bucket ACL modification detected",
            "weight":      35
        })
        score += 35

    # ── R-07: Security group ingress rule added ─────────────────────────────────
    # New inbound rules on security groups may expose resources to the internet.
    # MITRE ATT&CK: T1562.007 (Impair Defences: Disable or Modify Cloud Firewall)
    if evt_name == "AuthorizeSecurityGroupIngress":
        triggered.append({
            "rule_id":     "R-07",
            "description": "Security group ingress rule added",
            "weight":      20
        })
        score += 20

    # ── R-08: CloudTrail logging stopped or deleted ─────────────────────────────
    # Defence evasion technique — disabling audit logging to hide subsequent
    # malicious activity. Highest individual rule weight.
    # MITRE ATT&CK: T1562.008 (Impair Defences: Disable Cloud Logs)
    if evt_name in ["StopLogging", "DeleteTrail"]:
        triggered.append({
            "rule_id":     "R-08",
            "description": "CloudTrail logging stopped or deleted",
            "weight":      45
        })
        score += 45

    # ── R-09: New IAM user created ──────────────────────────────────────────────
    # Unexpected user creation may indicate persistence establishment.
    # MITRE ATT&CK: T1136.003 (Create Account: Cloud Account)
    if evt_name == "CreateUser":
        triggered.append({
            "rule_id":     "R-09",
            "description": "New IAM user created",
            "weight":      10
        })
        score += 10

    # ── R-10: Access key created for root or unknown user ──────────────────────
    # Programmatic access keys for the root account are prohibited under
    # AWS security best practices.
    # MITRE ATT&CK: T1098.001 (Account Manipulation: Additional Cloud Credentials)
    if evt_name == "CreateAccessKey" and user_type in ["Root", ""]:
        triggered.append({
            "rule_id":     "R-10",
            "description": "Access key created for privileged user",
            "weight":      30
        })
        score += 30

    # Cap composite score at 100
    score = min(score, 100)
    return triggered, score


def determine_severity(score):
    """
    Classify composite threat score into severity tier.

    Thresholds:
        HIGH:   score >= 70
        MEDIUM: score >= 40
        LOW:    score <  40
    """
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"


def store_event(event, triggered_rules, score, severity):
    """
    Persist processed security event to DynamoDB audit table.

    Stores full forensic record including raw payload, triggered rules,
    computed score, severity classification, and UUID event ID.

    Returns:
        tuple: (event_id str, timestamp str)
    """
    event_id  = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    item = {
        "event_id":        event_id,
        "timestamp":       timestamp,
        "source":          event.get("source", "unknown"),
        "event_name":      event.get("raw_event", {}).get("eventName", "unknown"),
        "user_identity":   json.dumps(
                               event.get("raw_event", {}).get("userIdentity", {})
                           ),
        "source_ip":       event.get("raw_event", {}).get("sourceIPAddress", "unknown"),
        "threat_score":    score,
        "severity":        severity,
        "triggered_rules": json.dumps(triggered_rules),
        "raw_event":       json.dumps(event.get("raw_event", {})),
        "response_action": "PENDING"
    }

    table.put_item(Item=item)
    return event_id, timestamp


def send_alert(event, triggered_rules, score, severity, event_id):
    """
    Publish SNS notification for MEDIUM and HIGH severity events.

    LOW severity events are stored in DynamoDB only — no alert is sent.
    Alert content includes event details, triggered rules with weights,
    and a recommended response action.
    """
    if severity == "LOW":
        return

    event_name = event.get("raw_event", {}).get("eventName", "unknown")
    source_ip  = event.get("raw_event", {}).get("sourceIPAddress", "unknown")
    rules_text = "\n".join([
        f"  - [{r['rule_id']}] {r['description']} (weight: {r['weight']})"
        for r in triggered_rules
    ])

    message = f"""
SIEM ALERT — {severity} SEVERITY THREAT DETECTED
================================================
Event ID    : {event_id}
Threat Score: {score}/100
Severity    : {severity}
Event Name  : {event_name}
Source      : {event.get('source', 'unknown')}
Source IP   : {source_ip}

Triggered Rules:
{rules_text}

Recommended Action:
{"IMMEDIATE: Disable IAM user, revoke sessions, isolate affected resources"
 if severity == "HIGH"
 else "INVESTIGATE: Review IAM permissions and enable MFA"}

This alert was generated by the SIEM Correlation Engine.
""".strip()

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[SIEM {severity}] {event_name} — Score: {score}/100",
        Message=message
    )


def lambda_handler(event, context):
    """
    Main Lambda entry point.

    Accepts security events in three formats:
    1. Direct invocation: raw event dict with 'source' and 'raw_event' keys
    2. API Gateway proxy: event dict with 'body' key (JSON string)
    3. EventBridge/GuardDuty: event dict with 'detail' key

    Returns:
        dict: statusCode 200 with JSON body containing event_id, threat_score,
              severity, rules_triggered count, and triggered_rules list.
    """
    print(f"Processing event: {json.dumps(event)}")

    # Normalise event format
    if "body" in event:
        security_event = json.loads(event["body"])
    elif "detail" in event:
        security_event = {
            "source":    "guardduty",
            "raw_event": event["detail"]
        }
    else:
        security_event = event

    # Run correlation engine
    triggered_rules, score = evaluate_rules(security_event)
    severity = determine_severity(score)

    print(f"Score: {score}, Severity: {severity}, "
          f"Rules triggered: {len(triggered_rules)}")

    # Persist to DynamoDB
    event_id, timestamp = store_event(
        security_event, triggered_rules, score, severity
    )

    # Send SNS alert (MEDIUM and HIGH only)
    send_alert(security_event, triggered_rules, score, severity, event_id)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "event_id":        event_id,
            "timestamp":       timestamp,
            "threat_score":    score,
            "severity":        severity,
            "rules_triggered": len(triggered_rules),
            "triggered_rules": triggered_rules
        })
    }
