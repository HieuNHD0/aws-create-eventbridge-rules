# aws-create-eventbridge-rules
### Background
- Monitoring of only one AWS account’s events (by sending events/alarms to Slack) is simple, you just need to set up that one account:
![image](https://user-images.githubusercontent.com/128770464/233538813-6a76e968-68b9-49b2-bae0-10602545c0d9.png)
- But if you have multiple accounts, setting up that flow one by one can be a problem. You might want to use EventBridge’s cross-account event bus to consolidate events from multiple accounts to a single account:
![image](https://user-images.githubusercontent.com/128770464/233538844-8c9ce998-56a9-44a0-915d-e1caa83f3378.png)
- This script's purpose is to simplify the process of creating the same EventBridge rules in many accounts
### How to use
- Requirements:
  + Know how to work with Git.
  + Know how to work with Python.
  + Know how to work with AWS CLI.
- Steps:
  1. Clone this repo to local.
  2. Log in AWS in local terminal (aws configure). Make sure that your account has AdministratorAccess role attached for all child accounts.
  3. Go to file accounts_config.yml, put all the accounts that you want to forward events to the central account in. For example:
```
target_accounts:
  - name: 'childaccount1'
    role_arn: 'arn:aws:iam::111111111111:role/LoginRoleAdministratorAccess'
    id: '111111111111'
    rules: ['rule1','rule2']
  - name: 'childaccount2'
    role_arn: 'arn:aws:iam::111111111112:role/LoginRoleAdministratorAccess'
    id: '111111111112'
    rules: ['rule1']
```
  4. Go to rules_config.yml, put in the rules to set the events that you want to forward to the central account. For example, the following rules are for AWS Health and RDS:
```
rules:
- id: 'rule1'
    name: 'forward-health-events'
    event_pattern: "{\"source\":[\"aws.health\"]}"
    description: 'Forward all health events to Central account'
    target_arn: 'arn:aws:events:ap-northeast-1:222222222222:event-bus/default'
    region: 'ap-southeast-1'
- id: 'rule2'
    name: 'forward-rds-events'
    event_pattern: "{\"source\": [\"aws.rds\"]}"
    description: 'Forward all RDS events to Central account'
    target_arn: 'arn:aws:events:ap-northeast-1:22222222222:event-bus/default'
    region: 'ap-southeast-1'
```
  5. Run the script:
    + With one account `python main.py --account 'account_name'`
    + With multiple accounts `python main.py --account 'list_of_account'` (accounts need to be separated by a comma ",". For example: `python main.py --account 'account1','account2','account3'`)
    + With all accounts python main.py --all-account true
