#!/usr/bin/env python
''' Query Security Hub, send Inspector get_findings to SNS topic'''

import boto3
import logging

#AWS region 
REGION = 'us-east-1'
#Max number of items for paginator to return
MAX_ITEMS=10
#AWS account ID for filter
AWS_ACCOUNT_ID = str(boto3.client('sts').get_caller_identity()['Account'])
#SQS Queue URL
TOPIC_ARN = 'string'

filters = {
  'Type': [
    {
      'Value': 'Software and Configuration Checks/AWS Security Best Practices/Network Reachability',
      'Comparison': 'PREFIX'
    }
  ],
  'AwsAccountId': [
    {
      'Value': AWS_ACCOUNT_ID,
      'Comparison': 'EQUALS'
    },
  ],
  'ProductName':[
    {
      'Value': 'Inspector',
      'Comparison': 'EQUALS'
    }
  ],
  'SeverityProduct':[
    {
      'Gte': 1
    }
  ],
  'CreatedAt':[
    {
      'DateRange': {
        'Value': 7,
        'Unit': 'DAYS'
      }
    }
  ]
}

def  main():
  logger = logging.getLogger()
  logger.setLevel(logging.INFO)
  logging.info("Starting...")
  getSecurityHubFindings()

def paginate(method, **kwargs):
      client = method.__self__
      paginator = client.get_paginator(method.__name__)
      for page in paginator.paginate(**kwargs).result_key_iters():
          for result in page:
              yield result

def getSecurityHubFindings():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    logging.info("Starting Lambda")
    
    hub = boto3.client('securityhub')
    sns = boto3.client('sns')
    findingsList = []
    for key in paginate(hub.get_findings, Filters=filters, PaginationConfig={'MaxItems': MAX_ITEMS}):
        scantype = key['Types']
        port=key['ProductFields']['attributes:2/value']
        vgw=key['ProductFields']['attributes:3/value']
        scantype = key['Types']
        findingAccountId = key['AwsAccountId']
        findingLastObservedAt=key['LastObservedAt']
        findingFirstObservedAt=key['FirstObservedAt']
        findingCreatedAt=key['CreatedAt']
        findingrecommendation=key['Remediation']['Recommendation']
        findingTypes=key['Types']
        InstanceId=key['Resources'][0]['Id']
        findingInstanceId=str(InstanceId)
        findingAppCode=key['Resources'][0]['Tags']['AppCode']
        findingGeneratorId=key['GeneratorId']
        findingProductArn=key['ProductArn']
        findingTitle=key['Title']
        findingsList.append(key)

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject='Inspector findings',
        Message=f"{findingAccountId}, {findingGeneratorId}, {findingTitle},{findingProductArn},{findingAppCode},{findingFirstObservedAt},{findingLastObservedAt},{findingCreatedAt},{findingrecommendation},{findingTypes},{port},{vgw},{findingInstanceId}",
        MessageAttributes={
            "scantype":{
                "DataType": "String",
                "StringValue": str(scantype)
            },
            "port":{
                "DataType": "String",
                "StringValue": str(port)
            },
            "vgw":{
                "DataType": "String",
                "StringValue": str(vgw)
            },
            "findingAccountId":{
                "DataType": "String",
                "StringValue": str(findingAccountId)
            },
            "findingLastObservedAt":{
                "DataType": "String",
                "StringValue": str(findingLastObservedAt)
            },
            "findingCreatedAt":{
                "DataType": "String",
                "StringValue": str(findingCreatedAt)
            },
            "findingrecommendation":{
                "DataType": "String",
                "StringValue": str(findingrecommendation)
            },
            "findingTypes":{
                "DataType": "String",
                "StringValue": str(findingTypes)
            },
            "InstanceId":{
                "DataType": "String",
                "StringValue": str(InstanceId)
            },
                "findingInstanceId":{
                "DataType": "String",
                "StringValue": str(findingInstanceId)
            },
                "findingAppCode":{
                "DataType": "String",
                "StringValue": str(findingAppCode)
            },
                "findingGeneratorId":{
                "DataType": "String",
                "StringValue": str(findingGeneratorId)
            },
                "findingProductArn":{
                "DataType": "String",
                "StringValue": str(findingProductArn)
            },
            "findingTitle":{
                "DataType": "String",
                "StringValue": str(findingTitle)
            }
        }
)

if __name__ == "__main__":
  main()
