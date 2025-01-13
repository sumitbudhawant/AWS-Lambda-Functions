import boto3
import json
from datetime import datetime, timezone
import os

def lambda_handler(event, context):
    findings = []
    
    # Initialize AWS clients
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')
    sns = boto3.client('sns')
    
    # Check for exposed security groups
    def check_security_groups():
        response = ec2.describe_security_groups()
        exposed_sgs = []
        
        for sg in response['SecurityGroups']:
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        exposed_sgs.append({
                            'GroupId': sg['GroupId'],
                            'GroupName': sg['GroupName'],
                            'Port': rule.get('FromPort', 'All'),
                            'Protocol': rule.get('IpProtocol', 'All')
                        })
        
        return exposed_sgs

    # Check for unencrypted EBS volumes
    def check_unencrypted_volumes():
        response = ec2.describe_volumes()
        return [{
            'VolumeId': vol['VolumeId'],
            'Size': vol['Size'],
            'State': vol['State']
        } for vol in response['Volumes'] if not vol['Encrypted']]

    # Check for IAM users with old access keys
    def check_access_keys():
        response = iam.list_users()
        old_keys = []
        
        for user in response['Users']:
            keys = iam.list_access_keys(UserName=user['UserName'])
            for key in keys['AccessKeyMetadata']:
                age = (datetime.now(timezone.utc) - key['CreateDate']).days
                if age > 90:  # Alert on keys older than 90 days
                    old_keys.append({
                        'UserName': user['UserName'],
                        'AccessKeyId': key['AccessKeyId'],
                        'Age': age
                    })
        
        return old_keys

    # Run all checks
    security_findings = {
        'exposed_security_groups': check_security_groups(),
        'unencrypted_volumes': check_unencrypted_volumes(),
        'old_access_keys': check_access_keys()
    }

    # Send findings if issues found
    if any(security_findings.values()):
        sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject='AWS Security Scan Findings',
            Message=json.dumps(security_findings, indent=2)
        )

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Security scan completed',
            'findings': security_findings
        })
    }