"""
Control Check: S3 Bucket Encryption
-----------------------------------------
Maps to:
  - NIST CSF 2.0: PR.DS-01 (Data-at-rest is protected)
  - ISO 27001 Annex A: A.8.24 (Use of cryptography)
  - SOC 2: CC6.1 (Logical access controls) / CC6.7 (Data transmission and disposal)

What it does:
  Connects to AWS S3 (read-only) and checks every bucket to see whether
  server-side encryption is enabled. Outputs a pass/fail report.

Why this control matters:
  Unencrypted storage means anyone who gains access to the underlying
  data (through a misconfiguration, a stolen credential, etc.) can read
  it in plain text. Encryption at rest is a baseline expectation in
  nearly every compliance framework and a standard check in tools like
  Vanta and Drata.

Requirements:
  pip install boto3
  AWS credentials configured locally (read-only IAM user recommended)
"""

import boto3

from datetime import datetime, timezone
from botocore.exceptions import ClientError


def get_all_buckets(s3_client):
    """Return a list of all S3 bucket names in the account."""
    response = s3_client.list_buckets()
    return [bucket["Name"] for bucket in response["Buckets"]]


def has_encryption_enabled(s3_client, bucket_name):
    """Return True if the given bucket has server-side encryption enabled."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        # AWS returns this specific error code when no encryption config exists
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        # Any other error (e.g. access denied) - re-raise so it's not hidden
        raise


def run_s3_encryption_check():
    s3 = boto3.client("s3")
    buckets = get_all_buckets(s3)

    results = []
    for bucket_name in buckets:
        encrypted = has_encryption_enabled(s3, bucket_name)
        results.append({
            "bucket": bucket_name,
            "encrypted": encrypted,
            "status": "PASS" if encrypted else "FAIL",
        })

    return results


def print_report(results):
    total = len(results)
    passed = sum(1 for r in results if r["encrypted"])
    failed = total - passed

    print("=" * 60)
    print("CONTROL CHECK: S3 Bucket Encryption")
    print("Mapped controls: NIST CSF PR.DS-01 | ISO 27001 A.8.24 | SOC2 CC6.1")
    print(f"Run at: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    for r in results:
        marker = "PASS" if r["encrypted"] else "FAIL"
        print(f"[{marker}] {r['bucket']:<40} {r['status']}")

    print("-" * 60)
    print(f"Total buckets: {total} | Passed: {passed} | Failed: {failed}")

    if failed == 0:
        print("Overall control status: PASS")
    else:
        print("Overall control status: FAIL - remediation required")
    print("=" * 60)


if __name__ == "__main__":
    results = run_s3_encryption_check()
    print_report(results)