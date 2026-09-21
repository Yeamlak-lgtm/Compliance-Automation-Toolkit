"""
Control Check: IAM User MFA Enforcement
-----------------------------------------
Maps to:
  - NIST CSF 2.0: PR.AC-07 (Users, devices, and other assets are authenticated
    commensurate with the risk of the transaction)
  - ISO 27001 Annex A: A.9.4.2 (Secure log-on procedures)
  - SOC 2: CC6.1 (Logical access controls)

What it does:
  Connects to AWS IAM (read-only) and checks every IAM user to see whether
  they have at least one MFA device registered. Outputs a pass/fail report.
"""

import boto3
from datetime import datetime, timezone


def get_all_iam_users(iam_client):
    """Return a list of all IAM users in the account."""
    users = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def has_mfa_enabled(iam_client, username):
    """Return True if the given IAM user has at least one MFA device."""
    response = iam_client.list_mfa_devices(UserName=username)
    return len(response["MFADevices"]) > 0


def run_mfa_check():
    iam = boto3.client("iam")
    users = get_all_iam_users(iam)

    results = []
    for user in users:
        username = user["UserName"]
        mfa_enabled = has_mfa_enabled(iam, username)
        results.append({
            "user": username,
            "mfa_enabled": mfa_enabled,
            "status": "PASS" if mfa_enabled else "FAIL",
        })

    return results


def print_report(results):
    total = len(results)
    passed = sum(1 for r in results if r["mfa_enabled"])
    failed = total - passed

    print("=" * 60)
    print("CONTROL CHECK: IAM User MFA Enforcement")
    print("Mapped controls: NIST CSF PR.AC-07 | ISO 27001 A.9.4.2 | SOC2 CC6.1")
    print(f"Run at: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    for r in results:
        marker = "PASS" if r["mfa_enabled"] else "FAIL"
        print(f"[{marker}] {r['user']:<30} {r['status']}")

    print("-" * 60)
    print(f"Total users: {total} | Passed: {passed} | Failed: {failed}")

    if failed == 0:
        print("Overall control status: PASS")
    else:
        print("Overall control status: FAIL - remediation required")
    print("=" * 60)


if __name__ == "__main__":
    results = run_mfa_check()
    print_report(results)
