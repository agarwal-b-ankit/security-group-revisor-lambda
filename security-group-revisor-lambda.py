import json
import boto3
import os
from botocore.exceptions import ClientError
from botocore.vendored import requests

def lambda_handler(event, context):
    print("INFO:: Lambda execution started")
    (securityGroupId,amazonRestURL,serviceTag,region, ruleDescription)=getInputs(event)
    ec2Client = boto3.client('ec2')
    aws_ips=get_aws_ips(amazonRestURL, serviceTag, region)
    sg_ips=get_sg_ips(ec2Client, securityGroupId, ruleDescription)
    
    print("INFO:: Figuring out existing IP's that needs to be removed")
    ips_to_remove = list(set(sg_ips).difference(aws_ips))
    if(ips_to_remove):
        remove_sg_permissions(ec2Client, securityGroupId, ips_to_remove, ruleDescription)
    else:
        print("INFO:: None of the existing ip's needs to be removed")
    
    print("INFO:: Figuring out new IP's that needs to be added")
    ips_to_add = list(set(aws_ips).difference(sg_ips))
    if(ips_to_add):
        add_sg_permissions(ec2Client, securityGroupId, ips_to_add, ruleDescription)
    else:
        print("INFO:: No new IP's needs to be added")
    print("INFO:: Lambda execution completed")
    return {
        'statusCode': 200,
        'body': json.dumps('Lambda executed successfully!')
    }

def getInputs(event):
    try:
        print("INFO:: Getting input parameters from event")
        (securityGroupId,amazonRestURL,serviceTag,region, ruleDescription)=getInputsFromEvent(event)
        return securityGroupId,amazonRestURL,serviceTag,region, ruleDescription
    except KeyError as e:
        print("INFO:: Couldn't find input parameter",e,"in the event object")
    try:
        print("INFO:: Getting input parameters from environment variables")
        (securityGroupId,amazonRestURL,serviceTag,region, ruleDescription)=getInputsFromEnvironment()
        return securityGroupId,amazonRestURL,serviceTag,region, ruleDescription
    except KeyError as e:
        print("INFO:: Couldn't find input parameter",e,"in the environment variables")
        raise

def getInputsFromEvent(event):
    securityGroupId=event['SecurityGroupId']
    amazonRestURL=event['AmazonRestURL']
    serviceTag=event['ServiceTag']
    region=event['Region']
    ruleDescription=' '.join(['Allow',serviceTag, region])
    print("INFO:: Input Parameters are:")
    print("INFO:: SecurityGroupId =",securityGroupId)
    print("INFO:: amazonRestURL =",amazonRestURL)
    print("INFO:: serviceTag =",serviceTag)
    print("INFO:: region =",region)
    print("INFO:: Rule Description =",ruleDescription)
    return securityGroupId,amazonRestURL,serviceTag,region, ruleDescription

def getInputsFromEnvironment():
    securityGroupId=os.environ['SecurityGroupId']
    amazonRestURL=os.environ['AmazonRestURL']
    serviceTag=os.environ['ServiceTag']
    region=os.environ['Region']
    ruleDescription=' '.join(['Allow',serviceTag, region])
    print("INFO:: Input Parameters are:")
    print("INFO:: SecurityGroupId =",securityGroupId)
    print("INFO:: amazonRestURL =",amazonRestURL)
    print("INFO:: serviceTag =",serviceTag)
    print("INFO:: region =",region)
    print("INFO:: Rule Description =",ruleDescription)
    return securityGroupId,amazonRestURL,serviceTag,region, ruleDescription

def get_aws_ips(amazonRestURL, serviceTag, region):
    try:
        print("INFO:: Retrieving AWS IP ranges for SERVICE =",serviceTag,"and region =",region)
        ipv4_ranges = requests.get(amazonRestURL).json()['prefixes']
        amazon_ipv4s = [item['ip_prefix'] for item in ipv4_ranges if item["service"] == serviceTag and item["region"] == region]
        print("INFO:: Finished retrieving AWS IP ranges")
        return amazon_ipv4s
    except:
        print("ERROR:: Error retrieving AWS IP ranges")
        raise

def get_sg_ips(ec2Client, securityGroupId, ruleDescription):
    response=None
    print("INFO:: Retrieving Security Group TCP 443 egress IP's with rule description:",ruleDescription)
    try:
        response = ec2Client.describe_security_groups(GroupIds=[securityGroupId])
    except ClientError as e:
        print("ERROR:: Client error while describing security group")
        raise
    ipPermissions=response['SecurityGroups'][0]['IpPermissionsEgress']
    httpsIpPermission=next((ipPermission for ipPermission in ipPermissions if ipPermission['IpProtocol']=='tcp' and ipPermission['FromPort']==443 and ipPermission['ToPort']==443),None)
    sg_ips = []
    if(httpsIpPermission is not None):
        sg_ips = [sg_ip['CidrIp'] for sg_ip in httpsIpPermission["IpRanges"] if sg_ip['Description']==ruleDescription]
    print("INFO:: Finished retrieving Security Group egress IP's")
    return sg_ips

def add_sg_permissions(ec2Client, securityGroupId, ips_to_add, ruleDescription):
    print("INFO:: Authorizing tcp 443 eggress rule for ip's: ", ips_to_add)
    ipRanges = [{"CidrIp":ip, 'Description':ruleDescription} for ip in ips_to_add]
    try:
        response = ec2Client.authorize_security_group_egress(GroupId=securityGroupId,IpPermissions=[{'IpProtocol': 'tcp',
            'FromPort': 443,
            'ToPort': 443,
            'IpRanges': ipRanges},
        ])
        print('INFO:: Egress rules added successfully: %s' % response)
    except ClientError as e:
        print('ERROR:: Client error while authorizing eggress rule')
        raise

def remove_sg_permissions(ec2Client, securityGroupId, ips_to_remove, ruleDescription):
    print("INFO:: Revoking tcp 443 eggress rule for ip's: ", ips_to_remove)
    ipRanges = [{"CidrIp":ip, 'Description':ruleDescription} for ip in ips_to_remove]
    try:
        response = ec2Client.revoke_security_group_egress(GroupId=securityGroupId,IpPermissions=[{'IpProtocol': 'tcp',
            'FromPort': 443,
            'ToPort': 443,
            'IpRanges': ipRanges},
        ])
        print('INFO:: Egress rules revoked successfully: %s' % response)
    except ClientError as e:
        print('ERROR:: Client error while revoking eggress rule')
        print(e)
