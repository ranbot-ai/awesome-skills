---
name: cloudformation
description: Deploy AWS resources with CloudFormation templates. Create stacks, use nested stacks, and implement drift detection. Use when deploying AWS-native IaC. 
category: AI & Agents
source: antigravity
tags: [ai, agent, template, image, security, aws, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudformation
---


# CloudFormation

Deploy AWS infrastructure with native CloudFormation templates, change sets, nested stacks, and drift detection.

## When to Use This Skill

- Deploying AWS resources using AWS-native Infrastructure as Code
- Creating repeatable, parameterized infrastructure templates
- Managing multi-environment deployments (dev, staging, prod) with the same template
- Implementing safe deployments with change sets and rollback protection
- Detecting and remediating configuration drift
- Organizing large infrastructure into nested stacks
- Exporting/importing values between stacks

## Prerequisites

- AWS CLI v2 installed and configured
- Least-privilege CloudFormation actions and a reviewed execution role/resource permissions scoped to the intended stacks
- (Optional) `cfn-lint` installed for template validation (`pip install cfn-lint`)
- S3 bucket for storing templates larger than 51,200 bytes

## Template Structure

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Production web application infrastructure

Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label: { default: "Environment" }
        Parameters: [Environment, InstanceType]
      - Label: { default: "Network" }
        Parameters: [VpcId, SubnetIds]

Parameters:
  Environment:
    Type: String
    AllowedValues: [dev, staging, prod]
    Default: dev

  InstanceType:
    Type: String
    Default: t3.micro
    AllowedValues: [t3.micro, t3.small, t3.medium, t3.large]

  AmiId:
    Type: AWS::EC2::Image::Id
    Description: Verified region-specific image with the application/bootstrap prerequisites

  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: VPC to deploy into

  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Subnets for the application

Conditions:
  IsProd: !Equals [!Ref Environment, prod]
  CreateReadReplica: !Equals [!Ref Environment, prod]

Resources:
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: !Sub '${Environment}-web-sg'
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-web-sg'

  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub '${Environment}-web'
      LaunchTemplateData:
        ImageId: !Ref AmiId
        InstanceType: !Ref InstanceType
        MetadataOptions:
          HttpTokens: required
        SecurityGroupIds:
          - !Ref SecurityGroup

  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: !Sub '${Environment}-web-asg'
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      MinSize: !If [IsProd, 2, 1]
      MaxSize: !If [IsProd, 10, 3]
      DesiredCapacity: !If [IsProd, 4, 1]
      VPCZoneIdentifier: !Ref SubnetIds
      TargetGroupARNs:
        - !Ref TargetGroup
      HealthCheckType: ELB
      HealthCheckGracePeriod: 300
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-web'
          PropagateAtLaunch: true
    UpdatePolicy:
      AutoScalingRollingUpdate:
        MinInstancesInService: !If [IsProd, 2, 0]
        MaxBatchSize: 1
        PauseTime: PT5M
        WaitOnResourceSignals: false # scaffold has no cfn-signal sender
        SuspendProcesses:
          - HealthCheck
          - ReplaceUnhealthy
          - AZRebalance
          - AlarmNotification
          - ScheduledActions

  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Name: !Sub '${Environment}-web-tg'
      Port: 8080
      Protocol: HTTP
      VpcId: !Ref VpcId
      TargetType: instance
      HealthCheckPath: /health
      HealthCheckIntervalSeconds: 30
      HealthyThresholdCount: 2
      UnhealthyThresholdCount: 3

Outputs:
  SecurityGroupId:
    Description: Web security group ID
    Value: !Ref SecurityGroup
    Export:
      Name: !Sub '${Environment}-WebSecurityGroup'

  AutoScalingGroupName:
    Description: ASG name
    Value: !Ref AutoScalingGroup
    Export:
      Name: !Sub '${Environment}-WebASG'
```

The template is an infrastructure scaffold, not a deployable production application: supply a verified region-specific AmiId and bootstrap/listener, an actual load balancer/listener and an ingress rule from its security group to target port8080. No cfn-signal sender is bundled, so resource-signal waiting is disabled; implement/test signals before enabling it. The nested child templates below are also external prerequisites.

## Stack Operations

```bash
# Validate a template
aws cloudformation validate-template --template-body file://template.yaml

# Lint with cfn-lint (catches more issues)
cfn-lint template.yaml

# Create a stack
aws cloudformation create-stack \
  --stack-name production-web \
  --template-body file://templa
