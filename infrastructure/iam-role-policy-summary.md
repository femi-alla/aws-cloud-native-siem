# IAM Role — siem-lambda-execution-role

## Trust Policy
Allows AWS Lambda service to assume this role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Attached Managed Policies (Prototype)

| Policy | Purpose |
|--------|---------|
| AmazonDynamoDBFullAccess | Read/write to siem-events table |
| AmazonSNSFullAccess | Publish to siem-alerts topic |
| CloudWatchFullAccess | Write execution logs |
| AmazonS3ReadOnlyAccess | Read log files from S3 |
| IAMFullAccess | Used during development only |

## Production Recommendation

Replace managed policies with inline policies scoped to specific resource ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Scan"],
      "Resource": "arn:aws:dynamodb:us-east-2:YOUR_ACCOUNT_ID:table/siem-events"
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-2:YOUR_ACCOUNT_ID:siem-alerts"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-2:YOUR_ACCOUNT_ID:*"
    }
  ]
}
```

This follows the principle of least privilege — each permission is scoped
to the exact resource and action required.
