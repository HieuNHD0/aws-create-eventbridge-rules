import boto3
import pdb 
import yaml
import json
import argparse
import time
import datetime

Event_Policy_name = 'AWS_Events_Invoke_Event_Bus'
Event_Role_name = 'AWS_Events_Invoke_Event_Bus'

accounts_config_file = './accounts_config.yml'
rules_config_file = './rules_config.yml'

target_accounts_config = {}
rules_config = {}
source_account_arn = ""

Event_Bus_Policy_Doc = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "events:PutEvents"
            ],
            "Resource": [
                "arn:aws:events:*:222222222222:event-bus/default" # replace your central account ID here
            ]
        }
    ]
}

Event_Bus_Role_Assume_Doc = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

### Load config of project account
def load_target_account(account_config_file):
    '''Load account config'''
    accounts_config = {}
    with open(account_config_file) as f:
        data = yaml.safe_load(f)
        for account in data['target_accounts']:
            name = account.get('name')
            role_arn = account.get('role_arn')
            id = account.get('id')
            rules = account.get('rules')
            accounts_config[name] = role_arn,id,rules
    return accounts_config

def load_source_account(account_config_file):
    '''Load account config'''
    source_role_arn = ''
    with open(account_config_file) as f:
        data = yaml.safe_load(f)
        source_role_arn = data['source_account']['role_arn']
    return source_role_arn

### Load rule config
def load_rules_config(rules_config_file):
  '''Load event config'''
  rules_config = {}
  with open(rules_config_file) as f:
    data = yaml.safe_load(f)
    for event in data['rules']:
        id = event.get('id')
        name = event.get('name')
        event_pattern =  event.get('event_pattern')
        description = event.get('description')
        target_arn = event.get('target_arn')
        region = event.get('region')
        rules_config[id] = name,event_pattern,description,target_arn,region
    return rules_config

def get_policy_arn(iam_client, policy_name):
    policies = iam_client.list_policies()['Policies']
    for policy in policies:
        if policy['PolicyName'] == policy_name:
            return policy['Arn']
    return None

def get_role_arn(iam_client, role_name):
    roles = iam_client.list_roles()['Roles']
    for role in roles:
        if role['RoleName'] == role_name:
            return role['Arn']
    return None


def create_dependency(session, policy_name, policy_document, role_name, role_document):
    iam_client = session.client('iam')
    policy_arn = get_policy_arn(iam_client, policy_name)
    if policy_arn == None:
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
        )['Policy']['Arn']
    role_arn = get_role_arn(iam_client, role_name)
    if role_arn == None:
        role_arn = iam_client.create_role(
            RoleName = role_name,
            AssumeRolePolicyDocument = json.dumps(role_document),
        )['Role']['Arn']
        #sleep to wait for the role become useable
        time.sleep(20)
    iam_client.attach_role_policy(
        RoleName = role_name,
        PolicyArn = policy_arn
    )
    return policy_arn,role_arn

# Add rule & set target to fw event to target account
def add_rule(client, rule_name, event_pattern, role_arn, description, target_arn):
    client.put_rule(
        Name=rule_name,
        EventPattern=event_pattern,
        State='ENABLED',
        Description = description,
        RoleArn = role_arn
    )
    client.put_targets(
        Rule = rule_name,
        Targets = [
            {
                'Id' : 'MyId', # Default id, don't need to change it
                'Arn': target_arn,
                'RoleArn': role_arn
            }
        ]
    )

def get_assume_session(role_arn,region):
    client = boto3.client('sts')
    response = client.assume_role(RoleArn=role_arn, RoleSessionName="tmp_session_for_audit_conf")
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                      aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                      aws_session_token=response['Credentials']['SessionToken'],
                      region_name=region)
    return session



def config_target_account(target_account,source_role_arn, target_role_arn, target_account_id, rule_id):
    rule_name,event_pattern,rule_description,target_arn,region = rules_config[rule_id]
    session = get_assume_session(target_role_arn,region)
    client = session.client('events')
    policy_arn, role_arn = create_dependency(session,Event_Policy_name, Event_Bus_Policy_Doc, Event_Role_name, Event_Bus_Role_Assume_Doc)
    add_rule(client, rule_name, event_pattern, role_arn, rule_description, target_arn)
    # add permision on source account:
    session = get_assume_session(source_role_arn,region)
    client = session.client('events')
    client.put_permission(
        Action='events:PutEvents',
        Principal=target_account_id,
        StatementId=target_account_id,
    )
    print("config rule %s on %s is successful" % (rule_name, target_account))

if __name__ == '__main__':
    ### parse input argument
    parser = argparse.ArgumentParser()
    parser.add_argument('--account', type=str, help='list of account need to config')
    parser.add_argument('--all-account', type=str, help='run all account')
    args = parser.parse_args()

    ### add cloudwatch rule on project account
    target_accounts_config = load_target_account(accounts_config_file)
    source_role_arn = load_source_account(accounts_config_file)
    rules_config = load_rules_config(rules_config_file)
    
    ### Run all account
    if (args.all_account == 'true') or (args.all_account == 'True'):
        target_accounts = target_accounts_config.keys()
    else:
        target_accounts=args.account.split(',')
    if len(target_accounts) > 0:
        for account in target_accounts:
            account = account.strip()
            target_role_arn, target_account_id, rule_ids = target_accounts_config[account]
            for rule_id in rule_ids:
                config_target_account(account, source_role_arn, target_role_arn, target_account_id, rule_id)


