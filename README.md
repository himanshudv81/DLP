# Solution to scenerio : Part 1
./N26_IT_Security_Take_Home_Assignment.pdf


# Solution to scenerio : Part 2

## AWS Security Assessment Script

## Overview

This Python script performs security assessments on an AWS environment, focusing on IAM, S3, and EC2 instances.


## How to Use

1. Clone the repository or download the script (`security_assessment.py`).

2. Configure AWS credentials:

    Ensure that your AWS credentials are properly configured.

4. Activate virtual env:

    ```bash
    source env/bin/activate
    ```

4. Run the script in virtual environment folder env:

    ```bash
    python AWS_Security_Assesment.py
    ```

5. Review the generated report:

    The script will create a report file named `security_assessment_report_<timestamp>.txt` with the assessment results in env folder.

    - **IAM Security Assessment:**
        - Check for overly permissive policies.
        - Review attached and inline policies.
        - Ensure MFA is enforced for privileged users.

    - **S3 Security Assessment:**
        - Check for public buckets.
        - Review ACLs and bucket policies.
        - Ensure server-side encryption is enabled.

    - **EC2 Security Assessment:**
        - Follow the principle of least privilege for security groups.
        - Avoid unrestricted access rules (0.0.0.0/0).
        - Regularly audit and review security group rules.

## How to Tackle Vulnerabilities

### IAM:
- **Overly Permissive Policies:**
    - Refine policies to grant the least privilege required for each user or role.
    - Use AWS IAM Policy Simulator to test and validate policies.

- **Unused or Stale Policies:**
    - Regularly review and remove unused or unnecessary policies.
    - Utilize AWS Access Advisor to identify unused permissions.

- **Credential Exposures:**
    - Rotate access keys regularly.
    - Use IAM roles with temporary credentials where possible.
    - Monitor IAM events in AWS CloudTrail for unusual activity.

### S3:
- **Bucket Permissions:**
    - Regularly audit and review S3 bucket ACLs and policies.
    - Utilize AWS S3 Block Public Access to prevent public access.

- **Public Access:**
    - Use bucket policies to restrict access.
    - Implement fine-grained access controls using IAM roles and policies.

- **Bucket Versioning:**
    - Enable versioning for critical buckets.
    - Regularly review and manage versioned objects.

### EC2:
- **Least Privilege Principle:**
    - Review and update security group rules to follow the principle of least privilege.
    - Utilize VPC Flow Logs to monitor and analyze traffic patterns.

- **Unrestricted Access:**
    - Avoid allowing unrestricted access to instances.
    - Use security groups to control inbound and outbound traffic.

- **Regular Audits:**
    - Regularly audit and update security group rules.
    - Remove any unnecessary rules.

## Security Best Practices

- Enable AWS Config to continuously assess and audit resource configurations.
- Utilize AWS CloudTrail to log all API calls and detect unusual activity.
- Consider implementing AWS Organizations for centralized management of multiple AWS accounts.