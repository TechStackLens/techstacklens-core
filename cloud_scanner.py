#!/usr/bin/env python3
"""
TechStackLens Cloud Scanner

This script collects AWS infrastructure information and generates JSON files 
compatible with the TechStackLens web application.

Usage:
  python cloud_scanner.py --scan-aws [--region us-east-1] [--services ec2,s3,rds]
"""

import os
import sys
import json
import argparse
import logging
import socket
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = Path("techstacklens_data")

class AWSScanner:
    """
    Scanner for AWS infrastructure that extracts EC2 instances, RDS databases,
    S3 buckets, and other AWS services.
    """
    
    def __init__(self, region=None):
        """
        Initialize the AWS Scanner.
        
        Args:
            region (str): AWS region to scan (e.g., 'us-east-1')
        """
        self.region = region or 'us-east-1'
        self.aws_available = self._check_aws_cli_installed()
        
        # Define services to scan
        self.services = {
            'ec2': self._scan_ec2,
            'rds': self._scan_rds,
            's3': self._scan_s3,
            'lambda': self._scan_lambda,
            'apigateway': self._scan_api_gateway,
            'elbv2': self._scan_load_balancers,
            'cloudfront': self._scan_cloudfront,
            'dynamodb': self._scan_dynamodb,
            'elasticache': self._scan_elasticache,
            'sqs': self._scan_sqs,
            'sns': self._scan_sns
        }
    
    def scan(self, services=None):
        """
        Scan AWS infrastructure.
        
        Args:
            services (list): List of AWS services to scan. If None, scan all supported services.
            
        Returns:
            dict: AWS scan results
        """
        logger.info(f"Starting AWS infrastructure scan in region {self.region}")
        
        if not self.aws_available:
            logger.error("AWS CLI not installed or not configured")
            return {"aws_scan": {"error": "AWS CLI not installed or not configured"}}
        
        results = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "region": self.region,
                "caller_identity": self._get_caller_identity()
            },
            "resources": {}
        }
        
        # Determine which services to scan
        services_to_scan = services or list(self.services.keys())
        
        # Scan each selected service
        for service in services_to_scan:
            if service in self.services:
                try:
                    logger.info(f"Scanning AWS {service}...")
                    scan_function = self.services[service]
                    service_results = scan_function()
                    results["resources"][service] = service_results
                except Exception as e:
                    logger.error(f"Error scanning AWS {service}: {e}")
                    results["resources"][service] = {"error": str(e)}
            else:
                logger.warning(f"Service {service} not supported for scanning")
        
        logger.info("AWS infrastructure scan completed")
        return {"aws_scan": results}
    
    def _check_aws_cli_installed(self):
        """Check if AWS CLI is installed and configured."""
        try:
            import subprocess
            process = subprocess.run(["aws", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                return False
            
            # Check if AWS CLI is configured
            process = subprocess.run(["aws", "sts", "get-caller-identity"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                logger.warning("AWS CLI is installed but not configured properly")
                return False
            
            return True
        except Exception:
            return False
    
    def _run_aws_command(self, command):
        """
        Run an AWS CLI command and return the JSON result.
        
        Args:
            command (list): AWS CLI command as a list of strings
            
        Returns:
            dict: Parsed JSON output
        """
        try:
            import subprocess
            
            # Add region to command if not already included
            if '--region' not in command and '-r' not in command:
                command.extend(['--region', self.region])
            
            # Add output format
            command.extend(['--output', 'json'])
            
            process = subprocess.run(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                logger.error(f"Error running AWS command: {process.stderr}")
                return {}
            
            return json.loads(process.stdout)
        except Exception as e:
            logger.error(f"Error running AWS command: {e}")
            return {}
    
    def _get_caller_identity(self):
        """Get AWS caller identity information."""
        return self._run_aws_command(['aws', 'sts', 'get-caller-identity'])
    
    def _scan_ec2(self):
        """Scan EC2 instances."""
        logger.info("Scanning EC2 instances...")
        instances = []
        
        # Get EC2 instances
        result = self._run_aws_command(['aws', 'ec2', 'describe-instances'])
        
        if 'Reservations' not in result:
            return instances
        
        for reservation in result['Reservations']:
            for instance in reservation.get('Instances', []):
                # Extract relevant instance information
                instance_info = {
                    'id': instance.get('InstanceId'),
                    'type': instance.get('InstanceType'),
                    'state': instance.get('State', {}).get('Name'),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'launch_time': instance.get('LaunchTime'),
                    'tags': instance.get('Tags', []),
                    'security_groups': instance.get('SecurityGroups', [])
                }
                
                # Get instance name from tags
                for tag in instance.get('Tags', []):
                    if tag.get('Key') == 'Name':
                        instance_info['name'] = tag.get('Value')
                        break
                
                instances.append(instance_info)
        
        # Get security groups
        security_groups = self._scan_security_groups()
        
        return {
            'instances': instances,
            'security_groups': security_groups
        }
    
    def _scan_security_groups(self):
        """Scan EC2 security groups."""
        logger.info("Scanning EC2 security groups...")
        security_groups = []
        
        result = self._run_aws_command(['aws', 'ec2', 'describe-security-groups'])
        
        if 'SecurityGroups' not in result:
            return security_groups
        
        for sg in result['SecurityGroups']:
            sg_info = {
                'id': sg.get('GroupId'),
                'name': sg.get('GroupName'),
                'description': sg.get('Description'),
                'vpc_id': sg.get('VpcId'),
                'inbound_rules': sg.get('IpPermissions', []),
                'outbound_rules': sg.get('IpPermissionsEgress', [])
            }
            security_groups.append(sg_info)
        
        return security_groups
    
    def _scan_rds(self):
        """Scan RDS databases."""
        logger.info("Scanning RDS databases...")
        databases = []
        
        result = self._run_aws_command(['aws', 'rds', 'describe-db-instances'])
        
        if 'DBInstances' not in result:
            return databases
        
        for db in result['DBInstances']:
            db_info = {
                'id': db.get('DBInstanceIdentifier'),
                'engine': db.get('Engine'),
                'engine_version': db.get('EngineVersion'),
                'status': db.get('DBInstanceStatus'),
                'endpoint': db.get('Endpoint', {}).get('Address'),
                'port': db.get('Endpoint', {}).get('Port'),
                'instance_type': db.get('DBInstanceClass'),
                'storage': db.get('AllocatedStorage'),
                'multi_az': db.get('MultiAZ'),
                'vpc_id': db.get('DBSubnetGroup', {}).get('VpcId'),
                'subnet_group': db.get('DBSubnetGroup', {}).get('DBSubnetGroupName'),
                'security_groups': [sg.get('VpcSecurityGroupId') for sg in db.get('VpcSecurityGroups', [])]
            }
            databases.append(db_info)
        
        return databases
    
    def _scan_s3(self):
        """Scan S3 buckets."""
        logger.info("Scanning S3 buckets...")
        buckets = []
        
        # List buckets
        result = self._run_aws_command(['aws', 's3api', 'list-buckets'])
        
        if 'Buckets' not in result:
            return buckets
        
        for bucket in result['Buckets']:
            bucket_name = bucket.get('Name')
            
            # Get bucket location
            location_result = self._run_aws_command(['aws', 's3api', 'get-bucket-location', '--bucket', bucket_name])
            bucket_region = location_result.get('LocationConstraint') or 'us-east-1'
            
            # Only include buckets in the current region
            if bucket_region != self.region:
                continue
            
            bucket_info = {
                'name': bucket_name,
                'creation_date': bucket.get('CreationDate'),
                'region': bucket_region
            }
            
            # Get bucket website configuration if available
            try:
                website_result = self._run_aws_command(['aws', 's3api', 'get-bucket-website', '--bucket', bucket_name])
                if website_result:
                    bucket_info['website'] = {
                        'index_document': website_result.get('IndexDocument', {}).get('Suffix'),
                        'error_document': website_result.get('ErrorDocument', {}).get('Key')
                    }
            except Exception:
                pass
            
            buckets.append(bucket_info)
        
        return buckets
    
    def _scan_lambda(self):
        """Scan Lambda functions."""
        logger.info("Scanning Lambda functions...")
        functions = []
        
        result = self._run_aws_command(['aws', 'lambda', 'list-functions'])
        
        if 'Functions' not in result:
            return functions
        
        for func in result['Functions']:
            function_info = {
                'name': func.get('FunctionName'),
                'arn': func.get('FunctionArn'),
                'runtime': func.get('Runtime'),
                'memory': func.get('MemorySize'),
                'timeout': func.get('Timeout'),
                'last_modified': func.get('LastModified'),
                'handler': func.get('Handler'),
                'description': func.get('Description'),
                'vpc_config': func.get('VpcConfig')
            }
            
            # Get function tags
            try:
                tags_result = self._run_aws_command(['aws', 'lambda', 'list-tags', '--resource', function_info['arn']])
                function_info['tags'] = tags_result.get('Tags', {})
            except Exception:
                pass
            
            functions.append(function_info)
        
        return functions
    
    def _scan_api_gateway(self):
        """Scan API Gateway REST APIs."""
        logger.info("Scanning API Gateway REST APIs...")
        apis = []
        
        # Get REST APIs
        result = self._run_aws_command(['aws', 'apigateway', 'get-rest-apis'])
        
        if 'items' not in result:
            return apis
        
        for api in result['items']:
            api_info = {
                'id': api.get('id'),
                'name': api.get('name'),
                'description': api.get('description'),
                'created_date': api.get('createdDate'),
                'version': api.get('version'),
                'stages': []
            }
            
            # Get API stages
            try:
                stages_result = self._run_aws_command(['aws', 'apigateway', 'get-stages', '--rest-api-id', api_info['id']])
                if 'item' in stages_result:
                    for stage in stages_result['item']:
                        api_info['stages'].append({
                            'name': stage.get('stageName'),
                            'deployment_id': stage.get('deploymentId'),
                            'description': stage.get('description'),
                            'created_date': stage.get('createdDate'),
                            'last_updated_date': stage.get('lastUpdatedDate')
                        })
            except Exception:
                pass
            
            apis.append(api_info)
        
        return apis
    
    def _scan_load_balancers(self):
        """Scan Elastic Load Balancers (ALB/NLB)."""
        logger.info("Scanning Elastic Load Balancers...")
        load_balancers = []
        
        result = self._run_aws_command(['aws', 'elbv2', 'describe-load-balancers'])
        
        if 'LoadBalancers' not in result:
            return load_balancers
        
        for lb in result['LoadBalancers']:
            lb_info = {
                'arn': lb.get('LoadBalancerArn'),
                'name': lb.get('LoadBalancerName'),
                'type': lb.get('Type'),  # 'application' or 'network'
                'scheme': lb.get('Scheme'),
                'vpc_id': lb.get('VpcId'),
                'security_groups': lb.get('SecurityGroups', []),
                'availability_zones': lb.get('AvailabilityZones', []),
                'dns_name': lb.get('DNSName'),
                'state': lb.get('State', {}).get('Code'),
                'created_time': lb.get('CreatedTime'),
                'listeners': [],
                'target_groups': []
            }
            
            # Get listeners
            try:
                listeners_result = self._run_aws_command(['aws', 'elbv2', 'describe-listeners', 
                                                        '--load-balancer-arn', lb_info['arn']])
                if 'Listeners' in listeners_result:
                    lb_info['listeners'] = listeners_result['Listeners']
            except Exception:
                pass
            
            # Get target groups
            try:
                target_groups_result = self._run_aws_command(['aws', 'elbv2', 'describe-target-groups', 
                                                            '--load-balancer-arn', lb_info['arn']])
                if 'TargetGroups' in target_groups_result:
                    for tg in target_groups_result['TargetGroups']:
                        target_group = {
                            'arn': tg.get('TargetGroupArn'),
                            'name': tg.get('TargetGroupName'),
                            'protocol': tg.get('Protocol'),
                            'port': tg.get('Port'),
                            'vpc_id': tg.get('VpcId'),
                            'target_type': tg.get('TargetType'),
                            'health_check': tg.get('HealthCheckEnabled'),
                            'targets': []
                        }
                        
                        # Get targets
                        try:
                            targets_result = self._run_aws_command(['aws', 'elbv2', 'describe-target-health', 
                                                                  '--target-group-arn', target_group['arn']])
                            if 'TargetHealthDescriptions' in targets_result:
                                target_group['targets'] = targets_result['TargetHealthDescriptions']
                        except Exception:
                            pass
                        
                        lb_info['target_groups'].append(target_group)
            except Exception:
                pass
            
            load_balancers.append(lb_info)
        
        return load_balancers
    
    def _scan_cloudfront(self):
        """Scan CloudFront distributions."""
        logger.info("Scanning CloudFront distributions...")
        distributions = []
        
        result = self._run_aws_command(['aws', 'cloudfront', 'list-distributions'])
        
        if 'DistributionList' not in result or 'Items' not in result['DistributionList']:
            return distributions
        
        for dist in result['DistributionList']['Items']:
            dist_info = {
                'id': dist.get('Id'),
                'arn': dist.get('ARN'),
                'domain_name': dist.get('DomainName'),
                'status': dist.get('Status'),
                'enabled': dist.get('Enabled'),
                'price_class': dist.get('PriceClass'),
                'origins': dist.get('Origins', {}).get('Items', []),
                'aliases': dist.get('Aliases', {}).get('Items', []),
                'default_cache_behavior': dist.get('DefaultCacheBehavior', {}),
                'cache_behaviors': dist.get('CacheBehaviors', {}).get('Items', [])
            }
            
            distributions.append(dist_info)
        
        return distributions
    
    def _scan_dynamodb(self):
        """Scan DynamoDB tables."""
        logger.info("Scanning DynamoDB tables...")
        tables = []
        
        result = self._run_aws_command(['aws', 'dynamodb', 'list-tables'])
        
        if 'TableNames' not in result:
            return tables
        
        for table_name in result['TableNames']:
            # Get table details
            table_result = self._run_aws_command(['aws', 'dynamodb', 'describe-table', 
                                                '--table-name', table_name])
            
            if 'Table' not in table_result:
                continue
            
            table = table_result['Table']
            table_info = {
                'name': table.get('TableName'),
                'status': table.get('TableStatus'),
                'creation_date': table.get('CreationDateTime'),
                'provisioned_throughput': {
                    'read_capacity_units': table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits'),
                    'write_capacity_units': table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits')
                },
                'size_bytes': table.get('TableSizeBytes'),
                'item_count': table.get('ItemCount'),
                'key_schema': table.get('KeySchema', []),
                'attribute_definitions': table.get('AttributeDefinitions', []),
                'global_secondary_indexes': table.get('GlobalSecondaryIndexes', []),
                'local_secondary_indexes': table.get('LocalSecondaryIndexes', [])
            }
            
            tables.append(table_info)
        
        return tables
    
    def _scan_elasticache(self):
        """Scan ElastiCache clusters."""
        logger.info("Scanning ElastiCache clusters...")
        clusters = []
        
        result = self._run_aws_command(['aws', 'elasticache', 'describe-cache-clusters'])
        
        if 'CacheClusters' not in result:
            return clusters
        
        for cluster in result['CacheClusters']:
            cluster_info = {
                'id': cluster.get('CacheClusterId'),
                'status': cluster.get('CacheClusterStatus'),
                'engine': cluster.get('Engine'),
                'engine_version': cluster.get('EngineVersion'),
                'cache_node_type': cluster.get('CacheNodeType'),
                'num_cache_nodes': cluster.get('NumCacheNodes'),
                'preferred_availability_zone': cluster.get('PreferredAvailabilityZone'),
                'preferred_maintenance_window': cluster.get('PreferredMaintenanceWindow'),
                'cache_subnet_group_name': cluster.get('CacheSubnetGroupName'),
                'security_groups': [sg.get('SecurityGroupId') for sg in cluster.get('SecurityGroups', [])]
            }
            
            # Get cache nodes
            nodes = []
            for node in cluster.get('CacheNodes', []):
                node_info = {
                    'id': node.get('CacheNodeId'),
                    'status': node.get('CacheNodeStatus'),
                    'address': node.get('Endpoint', {}).get('Address'),
                    'port': node.get('Endpoint', {}).get('Port'),
                    'parameter_group_status': node.get('ParameterGroupStatus')
                }
                nodes.append(node_info)
            
            cluster_info['nodes'] = nodes
            
            clusters.append(cluster_info)
        
        return clusters
    
    def _scan_sqs(self):
        """Scan SQS queues."""
        logger.info("Scanning SQS queues...")
        queues = []
        
        result = self._run_aws_command(['aws', 'sqs', 'list-queues'])
        
        if 'QueueUrls' not in result:
            return queues
        
        for queue_url in result['QueueUrls']:
            # Get queue attributes
            attributes_result = self._run_aws_command(['aws', 'sqs', 'get-queue-attributes', 
                                                     '--queue-url', queue_url,
                                                     '--attribute-names', 'All'])
            
            if 'Attributes' not in attributes_result:
                continue
            
            attributes = attributes_result['Attributes']
            queue_info = {
                'url': queue_url,
                'name': queue_url.split('/')[-1],
                'arn': attributes.get('QueueArn'),
                'visibility_timeout': attributes.get('VisibilityTimeout'),
                'message_retention_period': attributes.get('MessageRetentionPeriod'),
                'maximum_message_size': attributes.get('MaximumMessageSize'),
                'delay_seconds': attributes.get('DelaySeconds'),
                'receive_message_wait_time_seconds': attributes.get('ReceiveMessageWaitTimeSeconds'),
                'approximate_number_of_messages': attributes.get('ApproximateNumberOfMessages')
            }
            
            queues.append(queue_info)
        
        return queues
    
    def _scan_sns(self):
        """Scan SNS topics."""
        logger.info("Scanning SNS topics...")
        topics = []
        
        result = self._run_aws_command(['aws', 'sns', 'list-topics'])
        
        if 'Topics' not in result:
            return topics
        
        for topic in result['Topics']:
            topic_arn = topic.get('TopicArn')
            topic_name = topic_arn.split(':')[-1]
            
            topic_info = {
                'arn': topic_arn,
                'name': topic_name,
                'subscriptions': []
            }
            
            # Get topic attributes
            attributes_result = self._run_aws_command(['aws', 'sns', 'get-topic-attributes', 
                                                     '--topic-arn', topic_arn])
            
            if 'Attributes' in attributes_result:
                topic_info['attributes'] = attributes_result['Attributes']
            
            # Get subscriptions
            subscriptions_result = self._run_aws_command(['aws', 'sns', 'list-subscriptions-by-topic', 
                                                        '--topic-arn', topic_arn])
            
            if 'Subscriptions' in subscriptions_result:
                for sub in subscriptions_result['Subscriptions']:
                    subscription_info = {
                        'arn': sub.get('SubscriptionArn'),
                        'protocol': sub.get('Protocol'),
                        'endpoint': sub.get('Endpoint')
                    }
                    topic_info['subscriptions'].append(subscription_info)
            
            topics.append(topic_info)
        
        return topics

class AzureScanner:
    """
    Scanner for Azure infrastructure that extracts VMs, App Services,
    Storage Accounts, and other Azure services.
    """
    
    def __init__(self, subscription_id=None):
        """
        Initialize the Azure Scanner.
        
        Args:
            subscription_id (str): Azure subscription ID
        """
        self.subscription_id = subscription_id
        self.azure_available = self._check_azure_cli_installed()
        
        # Define services to scan
        self.services = {
            'vm': self._scan_vms,
            'webapp': self._scan_app_services,
            'storage': self._scan_storage_accounts,
            'sql': self._scan_sql_databases,
            'cosmos': self._scan_cosmos_db,
            'keyvault': self._scan_key_vaults,
            'functionapp': self._scan_function_apps
        }
    
    def scan(self, services=None):
        """
        Scan Azure infrastructure.
        
        Args:
            services (list): List of Azure services to scan. If None, scan all supported services.
            
        Returns:
            dict: Azure scan results
        """
        logger.info("Starting Azure infrastructure scan")
        
        if not self.azure_available:
            logger.error("Azure CLI not installed or not configured")
            return {"azure_scan": {"error": "Azure CLI not installed or not configured"}}
        
        results = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "subscription_id": self.subscription_id or self._get_subscription_id()
            },
            "resources": {}
        }
        
        # Set subscription if provided
        if self.subscription_id:
            self._set_subscription(self.subscription_id)
        
        # Determine which services to scan
        services_to_scan = services or list(self.services.keys())
        
        # Scan each selected service
        for service in services_to_scan:
            if service in self.services:
                try:
                    logger.info(f"Scanning Azure {service}...")
                    scan_function = self.services[service]
                    service_results = scan_function()
                    results["resources"][service] = service_results
                except Exception as e:
                    logger.error(f"Error scanning Azure {service}: {e}")
                    results["resources"][service] = {"error": str(e)}
            else:
                logger.warning(f"Service {service} not supported for scanning")
        
        logger.info("Azure infrastructure scan completed")
        return {"azure_scan": results}
    
    def _check_azure_cli_installed(self):
        """Check if Azure CLI is installed and configured."""
        try:
            import subprocess
            process = subprocess.run(["az", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                return False
            
            # Check if Azure CLI is logged in
            process = subprocess.run(["az", "account", "show"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                logger.warning("Azure CLI is installed but not logged in")
                return False
            
            return True
        except Exception:
            return False
    
    def _run_azure_command(self, command):
        """
        Run an Azure CLI command and return the JSON result.
        
        Args:
            command (list): Azure CLI command as a list of strings
            
        Returns:
            dict or list: Parsed JSON output
        """
        try:
            import subprocess
            
            process = subprocess.run(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                logger.error(f"Error running Azure command: {process.stderr}")
                return {}
            
            return json.loads(process.stdout)
        except Exception as e:
            logger.error(f"Error running Azure command: {e}")
            return {}
    
    def _get_subscription_id(self):
        """Get the current Azure subscription ID."""
        result = self._run_azure_command(['az', 'account', 'show'])
        return result.get('id')
    
    def _set_subscription(self, subscription_id):
        """Set the active Azure subscription."""
        self._run_azure_command(['az', 'account', 'set', '--subscription', subscription_id])
    
    def _scan_vms(self):
        """Scan Azure Virtual Machines."""
        logger.info("Scanning Azure Virtual Machines...")
        vms = []
        
        result = self._run_azure_command(['az', 'vm', 'list', '--show-details', '-o', 'json'])
        
        if not isinstance(result, list):
            return vms
        
        for vm in result:
            vm_info = {
                'id': vm.get('id'),
                'name': vm.get('name'),
                'resource_group': vm.get('resourceGroup'),
                'location': vm.get('location'),
                'size': vm.get('hardwareProfile', {}).get('vmSize'),
                'os_type': vm.get('storageProfile', {}).get('osDisk', {}).get('osType'),
                'admin_username': vm.get('osProfile', {}).get('adminUsername'),
                'computer_name': vm.get('osProfile', {}).get('computerName'),
                'power_state': vm.get('powerState'),
                'provisioning_state': vm.get('provisioningState'),
                'network_interfaces': []
            }
            
            # Get network interfaces
            for nic in vm.get('networkProfile', {}).get('networkInterfaces', []):
                nic_id = nic.get('id')
                if nic_id:
                    nic_name = nic_id.split('/')[-1]
                    nic_result = self._run_azure_command(['az', 'network', 'nic', 'show', 
                                                        '--name', nic_name,
                                                        '--resource-group', vm_info['resource_group'],
                                                        '-o', 'json'])
                    
                    if nic_result:
                        nic_info = {
                            'id': nic_result.get('id'),
                            'name': nic_result.get('name'),
                            'private_ip': nic_result.get('ipConfigurations', [{}])[0].get('privateIpAddress'),
                            'public_ip': None
                        }
                        
                        # Get public IP if available
                        public_ip_id = nic_result.get('ipConfigurations', [{}])[0].get('publicIpAddress', {}).get('id')
                        if public_ip_id:
                            public_ip_name = public_ip_id.split('/')[-1]
                            public_ip_result = self._run_azure_command(['az', 'network', 'public-ip', 'show',
                                                                      '--name', public_ip_name,
                                                                      '--resource-group', vm_info['resource_group'],
                                                                      '-o', 'json'])
                            
                            if public_ip_result:
                                nic_info['public_ip'] = public_ip_result.get('ipAddress')
                        
                        vm_info['network_interfaces'].append(nic_info)
            
            vms.append(vm_info)
        
        return vms
    
    def _scan_app_services(self):
        """Scan Azure App Services (Web Apps)."""
        logger.info("Scanning Azure App Services...")
        web_apps = []
        
        result = self._run_azure_command(['az', 'webapp', 'list', '-o', 'json'])
        
        if not isinstance(result, list):
            return web_apps
        
        for app in result:
            app_info = {
                'id': app.get('id'),
                'name': app.get('name'),
                'resource_group': app.get('resourceGroup'),
                'location': app.get('location'),
                'state': app.get('state'),
                'enabled': app.get('enabled'),
                'host_names': app.get('hostNames', []),
                'default_host_name': app.get('defaultHostName'),
                'kind': app.get('kind'),
                'outbound_ip_addresses': app.get('outboundIpAddresses', '').split(',')
            }
            
            # Get app settings
            try:
                config_result = self._run_azure_command(['az', 'webapp', 'config', 'show',
                                                       '--name', app_info['name'],
                                                       '--resource-group', app_info['resource_group'],
                                                       '-o', 'json'])
                
                if config_result:
                    app_info['config'] = {
                        'always_on': config_result.get('alwaysOn'),
                        'php_version': config_result.get('phpVersion'),
                        'python_version': config_result.get('pythonVersion'),
                        'java_version': config_result.get('javaVersion'),
                        'node_version': config_result.get('nodeVersion'),
                        'linux_fx_version': config_result.get('linuxFxVersion'),
                        'windows_fx_version': config_result.get('windowsFxVersion'),
                        'http_logging_enabled': config_result.get('httpLoggingEnabled')
                    }
            except Exception:
                pass
            
            web_apps.append(app_info)
        
        return web_apps
    
    def _scan_storage_accounts(self):
        """Scan Azure Storage Accounts."""
        logger.info("Scanning Azure Storage Accounts...")
        storage_accounts = []
        
        result = self._run_azure_command(['az', 'storage', 'account', 'list', '-o', 'json'])
        
        if not isinstance(result, list):
            return storage_accounts
        
        for account in result:
            account_info = {
                'id': account.get('id'),
                'name': account.get('name'),
                'resource_group': account.get('resourceGroup'),
                'location': account.get('location'),
                'kind': account.get('kind'),
                'sku': account.get('sku', {}).get('name'),
                'provisioning_state': account.get('provisioningState'),
                'primary_endpoints': account.get('primaryEndpoints', {}),
                'encryption': account.get('encryption', {})
            }
            
            # List containers
            try:
                # Get the account keys first
                keys_result = self._run_azure_command(['az', 'storage', 'account', 'keys', 'list',
                                                     '--account-name', account_info['name'],
                                                     '-o', 'json'])
                
                if isinstance(keys_result, list) and len(keys_result) > 0:
                    account_key = keys_result[0].get('value')
                    
                    # List containers
                    containers_result = self._run_azure_command(['az', 'storage', 'container', 'list',
                                                              '--account-name', account_info['name'],
                                                              '--account-key', account_key,
                                                              '-o', 'json'])
                    
                    if isinstance(containers_result, list):
                        account_info['containers'] = [
                            {
                                'name': container.get('name'),
                                'public_access': container.get('properties', {}).get('publicAccess'),
                                'lease_state': container.get('properties', {}).get('leaseState')
                            }
                            for container in containers_result
                        ]
            except Exception:
                account_info['containers'] = []
            
            storage_accounts.append(account_info)
        
        return storage_accounts
    
    def _scan_sql_databases(self):
        """Scan Azure SQL Databases."""
        logger.info("Scanning Azure SQL Databases...")
        databases = []
        
        # First get SQL servers
        servers_result = self._run_azure_command(['az', 'sql', 'server', 'list', '-o', 'json'])
        
        if not isinstance(servers_result, list):
            return databases
        
        for server in servers_result:
            server_info = {
                'id': server.get('id'),
                'name': server.get('name'),
                'resource_group': server.get('resourceGroup'),
                'location': server.get('location'),
                'administrator_login': server.get('administratorLogin'),
                'fully_qualified_domain_name': server.get('fullyQualifiedDomainName'),
                'version': server.get('version'),
                'databases': []
            }
            
            # Get databases for this server
            db_result = self._run_azure_command(['az', 'sql', 'db', 'list',
                                               '--server', server_info['name'],
                                               '--resource-group', server_info['resource_group'],
                                               '-o', 'json'])
            
            if isinstance(db_result, list):
                for db in db_result:
                    db_info = {
                        'id': db.get('id'),
                        'name': db.get('name'),
                        'location': db.get('location'),
                        'status': db.get('status'),
                        'creation_date': db.get('creationDate'),
                        'max_size_bytes': db.get('maxSizeBytes'),
                        'sku': {
                            'name': db.get('sku', {}).get('name'),
                            'tier': db.get('sku', {}).get('tier'),
                            'capacity': db.get('sku', {}).get('capacity')
                        }
                    }
                    server_info['databases'].append(db_info)
            
            databases.append(server_info)
        
        return databases
    
    def _scan_cosmos_db(self):
        """Scan Azure Cosmos DB accounts."""
        logger.info("Scanning Azure Cosmos DB accounts...")
        cosmos_accounts = []
        
        result = self._run_azure_command(['az', 'cosmosdb', 'list', '-o', 'json'])
        
        if not isinstance(result, list):
            return cosmos_accounts
        
        for account in result:
            account_info = {
                'id': account.get('id'),
                'name': account.get('name'),
                'resource_group': account.get('resourceGroup'),
                'location': account.get('location'),
                'kind': account.get('kind', 'GlobalDocumentDB'),
                'consistency_policy': account.get('consistencyPolicy', {}),
                'capabilities': [cap.get('name') for cap in account.get('capabilities', [])],
                'enable_multiple_write_locations': account.get('enableMultipleWriteLocations', False),
                'document_endpoint': account.get('documentEndpoint'),
                'databases': []
            }
            
            # Get databases for this account
            try:
                db_result = self._run_azure_command(['az', 'cosmosdb', 'database', 'list',
                                                   '--name', account_info['name'],
                                                   '--resource-group', account_info['resource_group'],
                                                   '-o', 'json'])
                
                if isinstance(db_result, list):
                    for db in db_result:
                        db_info = {
                            'id': db.get('id'),
                            'name': db.get('name'),
                            'containers': []
                        }
                        
                        # Get containers for this database
                        try:
                            container_result = self._run_azure_command(['az', 'cosmosdb', 'sql', 'container', 'list',
                                                                      '--account-name', account_info['name'],
                                                                      '--database-name', db_info['name'],
                                                                      '--resource-group', account_info['resource_group'],
                                                                      '-o', 'json'])
                            
                            if isinstance(container_result, list):
                                for container in container_result:
                                    container_info = {
                                        'id': container.get('id'),
                                        'name': container.get('name'),
                                        'partition_key': container.get('resource', {}).get('partitionKey', {}).get('paths')
                                    }
                                    db_info['containers'].append(container_info)
                        except Exception:
                            pass
                        
                        account_info['databases'].append(db_info)
            except Exception:
                pass
            
            cosmos_accounts.append(account_info)
        
        return cosmos_accounts
    
    def _scan_key_vaults(self):
        """Scan Azure Key Vaults."""
        logger.info("Scanning Azure Key Vaults...")
        key_vaults = []
        
        result = self._run_azure_command(['az', 'keyvault', 'list', '-o', 'json'])
        
        if not isinstance(result, list):
            return key_vaults
        
        for vault in result:
            vault_info = {
                'id': vault.get('id'),
                'name': vault.get('name'),
                'resource_group': vault.get('resourceGroup'),
                'location': vault.get('location'),
                'sku': vault.get('properties', {}).get('sku', {}).get('name'),
                'tenant_id': vault.get('properties', {}).get('tenantId'),
                'vault_uri': vault.get('properties', {}).get('vaultUri'),
                'enabled_for_deployment': vault.get('properties', {}).get('enabledForDeployment', False),
                'enabled_for_disk_encryption': vault.get('properties', {}).get('enabledForDiskEncryption', False),
                'enabled_for_template_deployment': vault.get('properties', {}).get('enabledForTemplateDeployment', False),
                'secrets': [],
                'keys': [],
                'certificates': []
            }
            
            # Don't try to list secrets, keys, or certificates as it requires elevated permissions
            
            key_vaults.append(vault_info)
        
        return key_vaults
    
    def _scan_function_apps(self):
        """Scan Azure Function Apps."""
        logger.info("Scanning Azure Function Apps...")
        function_apps = []
        
        result = self._run_azure_command(['az', 'functionapp', 'list', '-o', 'json'])
        
        if not isinstance(result, list):
            return function_apps
        
        for app in result:
            app_info = {
                'id': app.get('id'),
                'name': app.get('name'),
                'resource_group': app.get('resourceGroup'),
                'location': app.get('location'),
                'state': app.get('state'),
                'host_names': app.get('hostNames', []),
                'default_host_name': app.get('defaultHostName'),
                'kind': app.get('kind'),
                'runtime': app.get('appSettings', {}).get('FUNCTIONS_WORKER_RUNTIME'),
                'version': app.get('appSettings', {}).get('FUNCTIONS_EXTENSION_VERSION')
            }
            
            # Get functions for this app
            try:
                functions_result = self._run_azure_command(['az', 'functionapp', 'function', 'list',
                                                          '--name', app_info['name'],
                                                          '--resource-group', app_info['resource_group'],
                                                          '-o', 'json'])
                
                if isinstance(functions_result, list):
                    app_info['functions'] = [
                        {
                            'name': func.get('name'),
                            'function_app_id': func.get('functionAppId'),
                            'script_root_path': func.get('scriptRootPath'),
                            'script_file': func.get('scriptFile'),
                            'config_href': func.get('config_href'),
                            'secrets_file_href': func.get('secrets_file_href'),
                            'href': func.get('href'),
                            'config': func.get('config', {})
                        }
                        for func in functions_result
                    ]
            except Exception:
                app_info['functions'] = []
            
            function_apps.append(app_info)
        
        return function_apps

class GCPScanner:
    """
    Scanner for Google Cloud Platform infrastructure that extracts 
    Compute Engine VMs, Cloud Storage buckets, and other GCP services.
    """
    
    def __init__(self, project_id=None):
        """
        Initialize the GCP Scanner.
        
        Args:
            project_id (str): GCP project ID
        """
        self.project_id = project_id
        self.gcp_available = self._check_gcloud_installed()
        
        # Define services to scan
        self.services = {
            'compute': self._scan_compute_instances,
            'storage': self._scan_storage_buckets,
            'sql': self._scan_cloud_sql,
            'functions': self._scan_cloud_functions,
            'app_engine': self._scan_app_engine,
            'gke': self._scan_kubernetes_clusters,
            'pubsub': self._scan_pubsub
        }
    
    def scan(self, services=None):
        """
        Scan GCP infrastructure.
        
        Args:
            services (list): List of GCP services to scan. If None, scan all supported services.
            
        Returns:
            dict: GCP scan results
        """
        logger.info("Starting GCP infrastructure scan")
        
        if not self.gcp_available:
            logger.error("Google Cloud SDK not installed or not configured")
            return {"gcp_scan": {"error": "Google Cloud SDK not installed or not configured"}}
        
        # If no project specified, get active project
        if not self.project_id:
            self.project_id = self._get_active_project()
            
        if not self.project_id:
            logger.error("No GCP project ID provided or found")
            return {"gcp_scan": {"error": "No GCP project ID provided or found"}}
        
        results = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "project_id": self.project_id
            },
            "resources": {}
        }
        
        # Determine which services to scan
        services_to_scan = services or list(self.services.keys())
        
        # Scan each selected service
        for service in services_to_scan:
            if service in self.services:
                try:
                    logger.info(f"Scanning GCP {service}...")
                    scan_function = self.services[service]
                    service_results = scan_function()
                    results["resources"][service] = service_results
                except Exception as e:
                    logger.error(f"Error scanning GCP {service}: {e}")
                    results["resources"][service] = {"error": str(e)}
            else:
                logger.warning(f"Service {service} not supported for scanning")
        
        logger.info("GCP infrastructure scan completed")
        return {"gcp_scan": results}
    
    def _check_gcloud_installed(self):
        """Check if Google Cloud SDK is installed and configured."""
        try:
            import subprocess
            process = subprocess.run(["gcloud", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                return False
            
            # Check if gcloud is authenticated
            process = subprocess.run(["gcloud", "auth", "list"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0 or "No credentialed accounts." in process.stdout:
                logger.warning("Google Cloud SDK is installed but not authenticated")
                return False
            
            return True
        except Exception:
            return False
    
    def _run_gcloud_command(self, command):
        """
        Run a gcloud command and return the JSON result.
        
        Args:
            command (list): gcloud command as a list of strings
            
        Returns:
            dict or list: Parsed JSON output
        """
        try:
            import subprocess
            
            # Add format json to command if not already included
            if '--format=json' not in command and '--format' not in ' '.join(command):
                command.extend(['--format=json'])
            
            # Add project if not already included
            if '--project' not in ' '.join(command) and self.project_id:
                command.extend(['--project', self.project_id])
            
            process = subprocess.run(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if process.returncode != 0:
                logger.error(f"Error running gcloud command: {process.stderr}")
                return {}
            
            return json.loads(process.stdout)
        except Exception as e:
            logger.error(f"Error running gcloud command: {e}")
            return {}
    
    def _get_active_project(self):
        """Get the current active GCP project."""
        result = self._run_gcloud_command(['gcloud', 'config', 'get-value', 'project'])
        if isinstance(result, str):
            return result.strip()
        return None
    
    def _scan_compute_instances(self):
        """Scan GCP Compute Engine instances."""
        logger.info("Scanning Compute Engine instances...")
        instances = []
        
        result = self._run_gcloud_command(['gcloud', 'compute', 'instances', 'list'])
        
        if not isinstance(result, list):
            return instances
        
        for instance in result:
            instance_info = {
                'id': instance.get('id'),
                'name': instance.get('name'),
                'zone': instance.get('zone').split('/')[-1] if instance.get('zone') else None,
                'machine_type': instance.get('machineType').split('/')[-1] if instance.get('machineType') else None,
                'status': instance.get('status'),
                'creation_timestamp': instance.get('creationTimestamp'),
                'cpu_platform': instance.get('cpuPlatform'),
                'disks': instance.get('disks', []),
                'network_interfaces': []
            }
            
            # Process network interfaces
            for interface in instance.get('networkInterfaces', []):
                interface_info = {
                    'name': interface.get('name'),
                    'network': interface.get('network').split('/')[-1] if interface.get('network') else None,
                    'subnetwork': interface.get('subnetwork').split('/')[-1] if interface.get('subnetwork') else None,
                    'network_ip': interface.get('networkIP'),
                    'access_configs': []
                }
                
                # Get external IPs
                for access_config in interface.get('accessConfigs', []):
                    interface_info['access_configs'].append({
                        'name': access_config.get('name'),
                        'type': access_config.get('type'),
                        'nat_ip': access_config.get('natIP')
                    })
                
                instance_info['network_interfaces'].append(interface_info)
            
            instances.append(instance_info)
        
        return instances
    
    def _scan_storage_buckets(self):
        """Scan GCP Cloud Storage buckets."""
        logger.info("Scanning Cloud Storage buckets...")
        buckets = []
        
        result = self._run_gcloud_command(['gcloud', 'storage', 'ls', '--json'])
        
        if not isinstance(result, list):
            return buckets
        
        for bucket in result:
            bucket_info = {
                'name': bucket.get('name'),
                'location': bucket.get('location'),
                'location_type': bucket.get('locationType'),
                'storage_class': bucket.get('storageClass'),
                'time_created': bucket.get('timeCreated'),
                'updated': bucket.get('updated'),
                'website_url': f"https://storage.googleapis.com/{bucket.get('name')}/index.html"
            }
            
            buckets.append(bucket_info)
        
        return buckets
    
    def _scan_cloud_sql(self):
        """Scan GCP Cloud SQL instances."""
        logger.info("Scanning Cloud SQL instances...")
        instances = []
        
        result = self._run_gcloud_command(['gcloud', 'sql', 'instances', 'list'])
        
        if not isinstance(result, list):
            return instances
        
        for instance in result:
            instance_info = {
                'name': instance.get('name'),
                'database_version': instance.get('databaseVersion'),
                'backend_type': instance.get('backendType'),
                'state': instance.get('state'),
                'region': instance.get('region'),
                'zone': instance.get('gceZone'),
                'tier': instance.get('settings', {}).get('tier'),
                'ip_addresses': [],
                'databases': []
            }
            
            # Process IP addresses
            for ip_mapping in instance.get('ipAddresses', []):
                instance_info['ip_addresses'].append({
                    'type': ip_mapping.get('type'),
                    'ip_address': ip_mapping.get('ipAddress')
                })
            
            # Get databases for this instance
            try:
                db_result = self._run_gcloud_command(['gcloud', 'sql', 'databases', 'list', 
                                                    '--instance', instance_info['name']])
                
                if isinstance(db_result, list):
                    for db in db_result:
                        instance_info['databases'].append({
                            'name': db.get('name'),
                            'charset': db.get('charset'),
                            'collation': db.get('collation')
                        })
            except Exception:
                pass
            
            instances.append(instance_info)
        
        return instances
    
    def _scan_cloud_functions(self):
        """Scan GCP Cloud Functions."""
        logger.info("Scanning Cloud Functions...")
        functions = []
        
        # Check if functions API is enabled
        apis_result = self._run_gcloud_command(['gcloud', 'services', 'list', 
                                              '--filter=name:cloudfunctions.googleapis.com'])
        
        if not isinstance(apis_result, list) or len(apis_result) == 0:
            logger.warning("Cloud Functions API is not enabled in this project")
            return functions
        
        # Get functions
        result = self._run_gcloud_command(['gcloud', 'functions', 'list'])
        
        if not isinstance(result, list):
            return functions
        
        for function in result:
            function_info = {
                'name': function.get('name').split('/')[-1] if function.get('name') else None,
                'status': function.get('status'),
                'entry_point': function.get('entryPoint'),
                'runtime': function.get('runtime'),
                'timeout': function.get('timeout'),
                'available_memory_mb': function.get('availableMemoryMb'),
                'service_account_email': function.get('serviceAccountEmail'),
                'update_time': function.get('updateTime'),
                'version_id': function.get('versionId'),
                'https_trigger': function.get('httpsTrigger', {}).get('url') if 'httpsTrigger' in function else None,
                'event_trigger': function.get('eventTrigger') if 'eventTrigger' in function else None
            }
            
            functions.append(function_info)
        
        return functions
    
    def _scan_app_engine(self):
        """Scan GCP App Engine applications."""
        logger.info("Scanning App Engine applications...")
        app_info = {}
        
        # Check if app exists
        try:
            app_result = self._run_gcloud_command(['gcloud', 'app', 'describe'])
            
            if app_result:
                app_info = {
                    'id': app_result.get('id'),
                    'name': app_result.get('name'),
                    'location_id': app_result.get('locationId'),
                    'serving_status': app_result.get('servingStatus'),
                    'default_hostname': app_result.get('defaultHostname'),
                    'services': []
                }
                
                # Get services
                services_result = self._run_gcloud_command(['gcloud', 'app', 'services', 'list'])
                
                if isinstance(services_result, list):
                    for service in services_result:
                        service_info = {
                            'id': service.get('id'),
                            'name': service.get('name'),
                            'versions': []
                        }
                        
                        # Get versions for this service
                        try:
                            versions_result = self._run_gcloud_command(['gcloud', 'app', 'versions', 'list',
                                                                      '--service', service_info['id']])
                            
                            if isinstance(versions_result, list):
                                for version in versions_result:
                                    service_info['versions'].append({
                                        'id': version.get('id'),
                                        'service': version.get('service'),
                                        'traffic_split': version.get('traffic_split'),
                                        'environment': version.get('environment'),
                                        'deployment': version.get('deployment', {})
                                    })
                        except Exception:
                            pass
                        
                        app_info['services'].append(service_info)
            else:
                logger.info("No App Engine application found in this project")
        except Exception as e:
            logger.error(f"Error scanning App Engine: {e}")
        
        return app_info
    
    def _scan_kubernetes_clusters(self):
        """Scan GCP GKE clusters."""
        logger.info("Scanning GKE clusters...")
        clusters = []
        
        result = self._run_gcloud_command(['gcloud', 'container', 'clusters', 'list'])
        
        if not isinstance(result, list):
            return clusters
        
        for cluster in result:
            cluster_info = {
                'name': cluster.get('name'),
                'location': cluster.get('location'),
                'master_version': cluster.get('currentMasterVersion'),
                'master_ip': cluster.get('endpoint'),
                'initial_node_count': cluster.get('initialNodeCount'),
                'node_config': cluster.get('nodeConfig', {}),
                'node_pools': []
            }
            
            # Get node pools for this cluster
            try:
                pools_result = self._run_gcloud_command(['gcloud', 'container', 'node-pools', 'list',
                                                       '--cluster', cluster_info['name'],
                                                       '--zone', cluster_info['location']])
                
                if isinstance(pools_result, list):
                    for pool in pools_result:
                        cluster_info['node_pools'].append({
                            'name': pool.get('name'),
                            'version': pool.get('version'),
                            'machine_type': pool.get('config', {}).get('machineType'),
                            'disk_size_gb': pool.get('config', {}).get('diskSizeGb'),
                            'initial_node_count': pool.get('initialNodeCount')
                        })
            except Exception:
                pass
            
            clusters.append(cluster_info)
        
        return clusters
    
    def _scan_pubsub(self):
        """Scan GCP Pub/Sub topics and subscriptions."""
        logger.info("Scanning Pub/Sub resources...")
        pubsub_info = {
            'topics': [],
            'subscriptions': []
        }
        
        # Get topics
        topics_result = self._run_gcloud_command(['gcloud', 'pubsub', 'topics', 'list'])
        
        if isinstance(topics_result, list):
            for topic in topics_result:
                topic_info = {
                    'name': topic.get('name').split('/')[-1] if topic.get('name') else None,
                    'full_name': topic.get('name'),
                    'message_storage_policy': topic.get('messageStoragePolicy'),
                    'kms_key_name': topic.get('kmsKeyName'),
                    'subscriptions': []
                }
                
                # Get subscriptions for this topic
                try:
                    subs_result = self._run_gcloud_command(['gcloud', 'pubsub', 'subscriptions', 'list',
                                                          '--filter=topic:' + topic_info['full_name']])
                    
                    if isinstance(subs_result, list):
                        for sub in subs_result:
                            topic_info['subscriptions'].append(sub.get('name').split('/')[-1] if sub.get('name') else None)
                except Exception:
                    pass
                
                pubsub_info['topics'].append(topic_info)
        
        # Get all subscriptions
        subs_result = self._run_gcloud_command(['gcloud', 'pubsub', 'subscriptions', 'list'])
        
        if isinstance(subs_result, list):
            for sub in subs_result:
                sub_info = {
                    'name': sub.get('name').split('/')[-1] if sub.get('name') else None,
                    'full_name': sub.get('name'),
                    'topic': sub.get('topic').split('/')[-1] if sub.get('topic') else None,
                    'ack_deadline_seconds': sub.get('ackDeadlineSeconds'),
                    'message_retention_duration': sub.get('messageRetentionDuration'),
                    'retain_acked_messages': sub.get('retainAckedMessages'),
                    'push_config': sub.get('pushConfig')
                }
                
                pubsub_info['subscriptions'].append(sub_info)
        
        return pubsub_info

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='TechStackLens Cloud Scanner')
    parser.add_argument('--scan-aws', action='store_true',
                        help='Scan AWS infrastructure')
    parser.add_argument('--scan-azure', action='store_true',
                        help='Scan Azure infrastructure')
    parser.add_argument('--scan-gcp', action='store_true',
                        help='Scan GCP infrastructure')
    parser.add_argument('--aws-region', type=str,
                        help='AWS region to scan (e.g., us-east-1)')
    parser.add_argument('--aws-services', type=str,
                        help='Comma-separated list of AWS services to scan (e.g., ec2,s3,rds)')
    parser.add_argument('--azure-subscription', type=str,
                        help='Azure subscription ID to scan')
    parser.add_argument('--azure-services', type=str,
                        help='Comma-separated list of Azure services to scan (e.g., vm,webapp,storage)')
    parser.add_argument('--gcp-project', type=str,
                        help='GCP project ID to scan')
    parser.add_argument('--gcp-services', type=str,
                        help='Comma-separated list of GCP services to scan (e.g., compute,storage,sql)')
    parser.add_argument('--output-dir', type=str, default='techstacklens_data',
                        help='Directory to save results (default: techstacklens_data)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    
    return parser.parse_args()

def ensure_output_dir(output_dir):
    """Ensure the output directory exists."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path

def save_results(data, output_dir, filename):
    """Save JSON data to file."""
    output_path = output_dir / filename
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Results saved to {output_path}")
    return output_path

def main():
    """Main function."""
    args = parse_arguments()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Ensure output directory exists
    output_dir = ensure_output_dir(args.output_dir)
    
    scan_results = {}
    
    # Perform AWS scan if requested
    if args.scan_aws:
        logger.info("Starting AWS infrastructure scan...")
        
        aws_services = args.aws_services.split(',') if args.aws_services else None
        aws_scanner = AWSScanner(region=args.aws_region)
        aws_results = aws_scanner.scan(services=aws_services)
        scan_results.update(aws_results)
        save_results(aws_results, output_dir, "aws_scan_results.json")
    
    # Perform Azure scan if requested
    if args.scan_azure:
        logger.info("Starting Azure infrastructure scan...")
        
        azure_services = args.azure_services.split(',') if args.azure_services else None
        azure_scanner = AzureScanner(subscription_id=args.azure_subscription)
        azure_results = azure_scanner.scan(services=azure_services)
        scan_results.update(azure_results)
        save_results(azure_results, output_dir, "azure_scan_results.json")
    
    # Perform GCP scan if requested
    if args.scan_gcp:
        logger.info("Starting GCP infrastructure scan...")
        
        gcp_services = args.gcp_services.split(',') if args.gcp_services else None
        gcp_scanner = GCPScanner(project_id=args.gcp_project)
        gcp_results = gcp_scanner.scan(services=gcp_services)
        scan_results.update(gcp_results)
        save_results(gcp_results, output_dir, "gcp_scan_results.json")
    
    # Save combined results
    if scan_results:
        save_results(scan_results, output_dir, "combined_scan_results.json")
        logger.info(f"All scan results have been saved to the {output_dir} directory")
        logger.info(f"Upload combined_scan_results.json to the TechStackLens web application")
    else:
        logger.warning("No scans were performed. Use --scan-aws, --scan-azure, or --scan-gcp flags.")
        print("\nUsage examples:")
        print("  python cloud_scanner.py --scan-aws --aws-region us-east-1")
        print("  python cloud_scanner.py --scan-azure")
        print("  python cloud_scanner.py --scan-gcp --gcp-project my-project")
        print("  python cloud_scanner.py --scan-aws --scan-azure --scan-gcp --verbose")

if __name__ == "__main__":
    try:
        print("\nTechStackLens Cloud Scanner")
        print("---------------------------")
        main()
        print("\nCollection completed. Check the techstacklens_data directory for results.")
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\nScan interrupted. Partial results may have been saved.")
    except Exception as e:
        logger.error(f"Error in cloud scanner: {e}", exc_info=True)
        print(f"\nAn error occurred: {e}")
        print("Check the logs for more details.")