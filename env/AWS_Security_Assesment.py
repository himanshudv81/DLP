import boto3
from botocore.exceptions import ClientError
from datetime import datetime

def check_iam(security_reports):
    security_reports.write("IAM Role Security Assessment:\n")
    try:
        # Creating boto3 IAM client
        iam_client = boto3.client('iam')

        # IAM users available in an AWS Account to variable users
        users = iam_client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            security_reports.write(f"\nAssessing IAM user: {user_name}\n")

            # Checking the attached policies with user
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            if attached_policies:
                security_reports.write(f"Attached Policies: {', '.join([policy['PolicyName'] for policy in attached_policies])}\n")
                
                # Check for overly permissive policies
                for policy in attached_policies:
                    policy_name = policy['PolicyName']
                    policy_details = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
                    if 'Statement' in policy_details and any('Effect' in stmt and stmt['Effect'] == 'Allow' and '*' in stmt.get('Action', []) for stmt in policy_details['Statement']):
                        security_reports.write(f"Overly permissive policy found in attached policy '{policy_name}'. Review and tighten policy for least privilege.\n")

                # Check MFA enforcement for privileged users (adjust as needed)
                if any('Administrator' in policy['PolicyName'] for policy in attached_policies):
                    user_info = iam_client.get_user(UserName=user_name)['User']
                    mfa_enabled = user_info.get('MFADevices')  # Use get() to avoid KeyError
                    if not mfa_enabled:
                        security_reports.write("MFA not enforced for Administrator. Enable MFA for enhanced security if user has console access.\n")

            else:
                security_reports.write("No attached policies.\n")

            # Checking the inline policies for the user
            inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
            if inline_policies:
                security_reports.write(f"Inline Policies: {', '.join(inline_policies)}\n")
                
                # Check for overly permissive inline policies
                for policy_name in inline_policies:
                    policy_details = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
                    if 'Statement' in policy_details and any('Effect' in stmt and stmt['Effect'] == 'Allow' and '*' in stmt.get('Action', []) for stmt in policy_details['Statement']):
                        security_reports.write(f"Overly permissive policy found in inline policy '{policy_name}'. Review and tighten policy for least privilege.\n")
            else:
                security_reports.write("No inline policies.\n")

    except ClientError as e:
        security_reports.write(f"Error while assessing IAM: {e}\n")

def check_s3(security_reports):
    security_reports.write("\nS3 Security Assessment:\n")
    try:
        # Creating boto3 S3 client
        s3_client = boto3.client('s3')

        # Listing all the S3 buckets
        buckets = [bucket['Name'] for bucket in s3_client.list_buckets()['Buckets']]

        for bucket_name in buckets:
            security_reports.write(f"\nAssessing S3 bucket: {bucket_name}\n")

            # Checking bucket ACL
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)['Grants']
            if acl:
                security_reports.write("Bucket ACL:\n")
                for grant in acl:
                    security_reports.write(str(grant) + "\n")
                
                # Check if the bucket is public
                public_access = any('URI' in grant['Grantee'] and 'http://acs.amazonaws.com/groups/global/AllUsers' in grant['Grantee']['URI'] for grant in acl)
                if public_access:
                    security_reports.write("Bucket is public. Restrict access and consider removing public permissions.\n")
            else:
                security_reports.write("No ACL defined for the bucket.\n")

            # Checking bucket policies
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
                if policy:
                    security_reports.write(f"Bucket Policy:\n{policy}\n")
                else:
                    security_reports.write("No bucket policy.\n")
            except ClientError:
                security_reports.write("No bucket policy.\n")

            # Check server-side encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)['ServerSideEncryptionConfiguration']
                if encryption and 'Rules' in encryption:
                    security_reports.write("Server-side encryption is enabled.\n")
                else:
                    security_reports.write("Server-side encryption is not enabled. Enable encryption for data at rest.\n")
            except ClientError as e:
                security_reports.write(f"Error checking server-side encryption: {e}\n")

    except ClientError as e:
        security_reports.write(f"Error assessing S3: {e}\n")

def check_ec2(security_reports):
    security_reports.write("\nEC2 Security Assessment:\n")
    try:
        # Creating boto3 EC2 client
        ec2_client = boto3.client('ec2')

        # Listing all security groups
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']

        for sg in security_groups:
            sg_name = sg['GroupName']
            security_reports.write(f"\nAssessing Security Group: {sg_name}\n")

            # Check security group rules
            ingress_rules = sg.get('IpPermissions', [])
            egress_rules = sg.get('IpPermissionsEgress', [])

            if ingress_rules or egress_rules:
                security_reports.write("Ingress Rules:\n")
                for rule in ingress_rules:
                    security_reports.write(str(rule) + "\n")

                    # Check for overly permissive ingress rules
                    if any('IpRanges' in rule and any('CidrIp' in ip_range and ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in rule['IpRanges']) for rule in ingress_rules):
                        security_reports.write("Overly permissive ingress rule found. Review and tighten security group rules for least privilege.\n")

                security_reports.write("\nEgress Rules:\n")
                for rule in egress_rules:
                    security_reports.write(str(rule) + "\n")

                    # Check for overly permissive egress rules
                    if any('IpRanges' in rule and any('CidrIp' in ip_range and ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in rule['IpRanges']) for rule in egress_rules):
                        security_reports.write("Overly permissive egress rule found. Review and tighten security group rules for least privilege.\n")
            else:
                security_reports.write("No inbound or outbound rules defined for the security group.\n")

    except ClientError as e:
        security_reports.write(f"Error assessing EC2: {e}\n")

def audit_security_report():
    #fetching current datetime for reporting
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = f"security_assessment_report_{current_datetime}.txt"
    
    #opening a file in write mode and saving the responses for each security check in the report
    with open(report, 'w') as security_reports:
        # Performs security assessment on iam roles
        check_iam(security_reports)
        # Performs security assessment on s3 buckets
        check_s3(security_reports)
        # Performs security assessment on ec2 security groups
        check_ec2(security_reports)

    print(f"Security assessments report saved to {report}")

if __name__ == "__main__":
    # Run the security audit on AWS Services and 
    # creates a report in the same folder as the python file with date and time : 
    # Example > ./security_assessment_report_2023-11-20_13-40-11.txt
    audit_security_report()