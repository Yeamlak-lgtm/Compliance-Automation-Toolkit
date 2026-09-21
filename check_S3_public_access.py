"""
Control Check: S3 Bucket Public Access Block
-----------------------------------------
Maps to:
  - NIST CSF 2.0: PR.AC-03 (Remote access is managed) / PR.DS-01 (Data-at-rest is protected)
  - ISO 27001 Annex A: A.8.24 (Use of cryptography) / A.8.3 (Information access restriction)
  - SOC 2: CC6.1 (Logical access controls)

What it does:
  Connects to AWS S3 (read-only) and checks every bucket to confirm that
  all four "Block Public Access" settings are enabled. Outputs a
  pass/fail report.

Why this control matters:
  Accidentally public S3 buckets are one of the most common real-world
  causes of data breaches - misconfigured buckets have exposed medical
  records, financial data, and government files in numerous incidents.
  This is one of the highest-priority checks any GRC/security tool runs.

Requirements:
  pip install boto3
  AWS credentials configured locally (read-only IAM user recommended)
"""

import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# The four settings that make up a bucket's full "Block Public Access" config
REQUIRED_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def get_all_buckets(s3_client):
    """Return a list of all S3 bucket names in the account."""
    response = s3_client.list_buckets()
    return [bucket["Name"] for bucket in response["Buckets"]]


def get_public_access_status(s3_client, bucket_name):
    """
    Return (is_fully_blocked, missing_settings) for a given bucket.
    is_fully_blocked is True only if all four settings are enabled.
    """
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
    except ClientError as e:
        # No public access block config exists at all = nothing is blocked
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False, REQUIRED_SETTINGS
        raise

    missing = [setting for setting in REQUIRED_SETTINGS if not config.get(setting, False)]
    return len(missing) == 0, missing


def run_s3_public_access_check():
    s3 = boto3.client("s3")
    buckets = get_all_buckets(s3)

    results = []
    for bucket_name in buckets:
        is_blocked, missing = get_public_access_status(s3, bucket_name)
        results.append({
            "bucket": bucket_name,
            "fully_blocked": is_blocked,
            "missing_settings": missing,
            "status": "PASS" if is_blocked else "FAIL",
        })

    return results


def print_report(results):
    total = len(results)
    passed = sum(1 for r in results if r["fully_blocked"])
    failed = total - passed

    print("=" * 60)
    print("CONTROL CHECK: S3 Bucket Public Access Block")
    print("Mapped controls: NIST CSF PR.AC-03 | ISO 27001 A.8.3 | SOC2 CC6.1")
    print(f"Run at: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    for r in results:
        marker = "PASS" if r["fully_blocked"] else "FAIL"
        print(f"[{marker}] {r['bucket']:<40} {r['status']}")
        if r["missing_settings"]:
            print(f"       Missing: {', '.join(r['missing_settings'])}")

    print("-" * 60)
    print(f"Total buckets: {total} | Passed: {passed} | Failed: {failed}")

    if failed == 0:
        print("Overall control status: PASS")
    else:
        print("Overall control status: FAIL - remediation required")
    print("=" * 60)


if __name__ == "__main__":
    results = run_s3_public_access_check()
    print_report(results)