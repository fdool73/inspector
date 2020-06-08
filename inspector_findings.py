#!/usr/bin/env python
''' Query Security Hub, export Inspector get_findings
boto reference: pagination and filtering: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/paginators.html
'''
import boto3
import base64
from datetime import datetime, timedelta
import datetime
import logging
import sys
import csv

REGION = 'us-east-1'

def  main():
  getSecurityHubFindings()
  
def csv_writer(file_name):
    with open(file_name, mode='w') as findings:
      findings_writer = csv.writer(findings, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
      findings_writer.writerow(['AwsAccountId', 'GeneratorId', 'Title','ProductArn','Severity','AppCode','FirstObservedAt','LastObservedAt','CreatedAt','Recommendation','Types','Port','VGW','PEERED_VPC','InstanceId'])

def paginate(method, **kwargs):
      client = method.__self__
      paginator = client.get_paginator(method.__name__)
      for page in paginator.paginate(**kwargs).result_key_iters():
          for result in page:
              yield result
  
def sendReport():
  pass
 
def getSecurityHubFindings():
  hub = boto3.client('securityhub')
  for key in paginate(hub.get_findings, Filters=filters):
    print(key.values())

 
def listSecurityHubMembers():
  hub = boto3.client('securityhub')
  for key in paginate(hub.list_members):
    print(key)
 
def getSecurityHubinsights():
  hub = boto3.client('securityhub')
  for key in paginate(hub.get_insights):
    print(key)

filters = {
  'Type': [
    {
      'Value': 'Software and Configuration Checks/AWS Security Best Practices/Network Reachability',
      'Comparison': 'PREFIX'
    }
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


if __name__ == "__main__":
  main()
