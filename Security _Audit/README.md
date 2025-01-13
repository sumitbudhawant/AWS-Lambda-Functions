# AWS Security Scan Lambda Function

This AWS Lambda function performs a security scan on your AWS environment, checking for exposed security groups, unencrypted EBS volumes, and IAM users with old access keys. If any issues are found, the findings are published to an SNS topic.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Functions](#functions)
- [Environment Variables](#environment-variables)
- [License](#license)

## Prerequisites

- AWS account with appropriate permissions.
- AWS IAM Role with the necessary permissions to describe security groups, describe volumes, list IAM users, and publish to SNS.

## Setup

1. Clone the repository:
    ```sh
    git clone https://github.com/sumitbudhawant/AWS-Lambda-Functions.git
    cd Security_Audit
    ```

2. Install the required dependencies (if applicable).

3. Deploy the Lambda function using your preferred method (e.g., AWS Console, AWS CLI, or using a deployment tool like Serverless Framework).

## Usage

1. Trigger the Lambda function manually or set it up to run on a schedule using Amazon CloudWatch Events.

2. The Lambda function will perform the following checks:
    - Exposed Security Groups
    - Unencrypted EBS Volumes
    - IAM Users with Old Access Keys

3. If any issues are found, the findings will be published to the specified SNS topic.

## Functions

- `check_security_groups()`: Checks for exposed security groups with rules allowing traffic from `0.0.0.0/0`.

- `check_unencrypted_volumes()`: Checks for unencrypted EBS volumes.

- `check_access_keys()`: Checks for IAM users with access keys older than 90 days.

- `lambda_handler(event, context)`: Main handler function that runs all checks and publishes findings if issues are found.

## Environment Variables

- `SNS_TOPIC_ARN`: ARN of the SNS topic to which the findings will be published.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Happy scanning!
