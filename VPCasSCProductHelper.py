# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import http.client
import ssl
import boto3
import json
from botocore.exceptions import ClientError
import os
from hashlib import md5
from base64 import b64encode
from ipaddress import IPv4Network
import urllib3
pool_manager = urllib3.PoolManager()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SCRIPT_VERSION = "1.0.0"
logger.info(f"Executing VPC as a Service Catalog Product Version {SCRIPT_VERSION}")

""" 
Description:
Gets the authorization header required for interactions with the Infoblox Grid.
 
Environment variables:
INFOBLOX_SECRET_NAME -- secret id of the secret in AWS Secrets Manager

Notes:
Infoblox username is stored in environment variable.
Infoblox password is stored in secrets manager. 
Example header returned: Basic ZXhhbXBsZVVzZXJuYW1lOmV4YW1wbGVQYXNzd29yZA==
"""
infoblox_username = os.environ['INFOBLOX_USERNAME']
def get_auth_header():
    secret_name = os.environ['INFOBLOX_SECRET_NAME']

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        logger.error(e)
        raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            raw_user_and_pass =  bytes(infoblox_username + ":" + secret, 'utf8')
            user_and_pass = b64encode(raw_user_and_pass).decode("ascii")
            header =  'Basic %s' %  user_and_pass
            return header


"""
Environment variables:
INFOBLOX_URL -- URL of Infoblox Grid
AWS_REGION -- region that the current lambda function resides (dynamically set by the lambda service)
NETWORK_VIEW -- Network view where VPC CIDR Blocks are stored in Infoblox Grid
NETWORK_SIZE -- Size of network to allocate to new VPC creation in child accounts
"""
auth_header = get_auth_header()
logger.debug(f"auth_header: {auth_header}")
infoblox_request_header = {
    'Authorization': auth_header
}
infoblox_url = os.environ['INFOBLOX_URL']
current_aws_region = os.environ['AWS_REGION']
network_view = os.environ['NETWORK_VIEW']
network_size = os.environ['NETWORK_SIZE']


""" 
Description:
Gets the next available cidr block for a VPC created by a child account.
 
Keyword arguments:
account_id -- account_id of the child account requesting a new VPC
stack_id -- stack_id of the VPC Cloudformation stack
 
Notes:
# This function when given an Account ID of a requester account
# will find all Network Containers allocated for the current lambda function region
# In the first available network container, the function will allocate a CIDR Block (Infoblox terminology: network) of size /26  with Cloud Account ID and current Region as extensible attributes
# returns the newly allocated CIDR Block

Scenarios: 
1. Add a CIDR Block to a region where multiple network containers exist
    # Expected: Add a network to the first free network container
2. Add a CIDR Block to a region where only a single network container exist
    # Expected: Add a network to the only available network container
3. Add a CIDR Block to a region where only a single network container exist which is full
    # Expected: Error Returned to User disallowing creation of the VPC
4. Add a CIDR Block to a region where no network containers exist
    # Expected: Error Returned to User disallowing creation of the VPC
"""
def get_cidr_block(account_id, stack_id):
    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    conn.request("GET", "/wapi/v2.7/networkcontainer?*Region="+ current_aws_region  + "&network_view=" + network_view, '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    
    logger.debug(f"raw network containers response: {result}")

    data = json.loads(result)
    networks =[]
    try:
        for entry in data:
            networks.append(entry['network'])
    except Exception:
        logger.error(f"unexpected response from network container: {result}")
        raise Exception("unexpected response from network container")

    logger.info(f"Network containers within this region: {networks}")

    if len(networks) == 0:
        raise Exception("No network containers are available in this region")

    for network in networks:
        raw_payload = {
            "network":f"func:nextavailablenetwork:{network},{network_view},{network_size}",
            "network_view":f"{network_view}",
            "extattrs": {
                "Region": {
                    "value": f"{current_aws_region}"
                },
                "Cloud Account ID": {
                    "value": f"{account_id}"
                },
                "Cloudformation Stack ID": {
                    "value": f"{stack_id}"
                }
            }
        }
        payload = json.dumps(raw_payload)

        conn.request("POST", "/wapi/v2.7/network", payload, infoblox_request_header)
        res = conn.getresponse()
        result = res.read().decode("utf-8")
        logger.info(f"Infoblox new network request response: {result}")
        
        # Successful results look like "network/ZG5zLm5ldHdvcmskMTQwLjE2OS42NS42NC8yNi82:140.169.65.64/26/AWS"
        if result.startswith("\"network") and result.endswith(f'{network_view}\"'):
            logger.info("Successfully added a new network to Infoblox")
            logger.info(result[result.index(':') + 1 : result.index('/' + network_view)])
            return result[result.index(':') + 1 : result.index('/' + network_view)]
        else:
             logger.warning(f"Current network container {network} resulted in an error.")
    
    raise Exception("All network containers resulted in errors.")


""" 
Description:
Deletes the next cidr block allocated for a VPC when deleted by a child account.
 
Keyword arguments:
account_id -- account_id of the child account deleting an existing VPC
stack_id -- stack_id of the VPC Cloudformation stack
 
Notes:
# This function when given an Account ID of a requester account
# will find all CIDR Blocks (Infoblox terminology: network) allocated for the current lambda function region and requester account ID
    # If there is more than one network allocated to an account ID and region, the function will raise an exception
    # If there is exactly one network  allocated to an account ID and region, the function will delete the CIDR Block (Infoblox terminology: network)
    # If there is exactly zero networks allocated to an account ID and region, the function will raise an exception
# returns null upon successful completion

Scenarios: 
1. Delete a CIDR Block where multiple networks have the same Account ID and Region extensible attribute
    # Expected: Error Returned to User disallowing deletion of the VPC
2. Delete a CIDR Block where a single network exists with the same Account ID and Region extensible attribute
    # Expected: Product and VPC is deleted from the customer account
3. Delete a CIDR Block where a zero networks exists with the same Account ID and Region extensible attribute
    # Expected: Error Returned to User disallowing deletion of the VPC
"""
def del_cidr_block(account_id, stack_id):
    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    payload = f"/wapi/v2.7/network?*Region={current_aws_region}&*Cloud+Account+ID={account_id}&*Cloudformation+Stack+ID={stack_id}&network_view={network_view}"
    conn.request("GET", payload, '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")

    logger.debug(f"All network: {result}")
    
    data = json.loads(result)
    networks =[]
    try:
        for entry in data:
            networks.append(entry['_ref'])
    except Exception:
        logger.error(f"unexpected response from network retrieval: {result}")
        raise Exception("unexpected response from network retrieval")

    logger.info("Networks associated with this account in this region: ")
    logger.info(networks)

    if len(networks) > 1:
        raise Exception("Found more than 1 network associated with this account and cloudformation stack id in this region")

    if len(networks) == 0:
        raise Exception("Found 0 networks associated with this account in this region")

    conn.request("DELETE", "/wapi/v2.7/" + networks[0], '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    logger.info(f"Delete request response: {result}")

    # Successful results look like "network/ZG5zLm5ldHdvcmskMTQwLjE2OS42Ni4wLzI2LzY:140.169.66.0/26/AWS"
    if result.startswith("\"network") and result.endswith(f'{network_view}\"'):
        logger.info("Successfully deleted a network from Infoblox")
        return
    
    raise Exception("Unable to successfully delete network from Infoblox.")

def split_cidr_block(cidr, num_of_subnet=2):
    network = IPv4Network(cidr)
    if num_of_subnet == 2:
        new_prefix_length = network.prefixlen + 1
        subnet_array = []
        raw_subnet_array = network.subnets(new_prefix=new_prefix_length)
        for subnet in raw_subnet_array:
            logger.debug(f"new subnet: {subnet}")
            subnet_array.append(str(subnet))
        logger.info(f"subnet_array: {subnet_array}")
        return subnet_array

""" 
Description:
Adds list of network containers to Infoblox Grid
 
Keyword arguments:
cidr_block_list -- comma delimited list of cidr blocks to add to the Infoblox Grid as network containers for this region
"""
def create_network_containers(cidr_block_list):
    cidr_block_list = cidr_block_list.replace(" ", "")
    for cidr_block in cidr_block_list.split(","):
        if cidr_block:
            create_network_container(cidr_block)

""" 
Description:
Adds single network container to Infoblox Grid
 
Keyword arguments:
cidr_block -- cidr block to add to the Infoblox Grid as network containers for this region
"""
def create_network_container(cidr_block):
    logger.info(f"Creating network container for {cidr_block} in Infoblox")

    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    raw_payload = {
        'network': cidr_block,
        'network_view': network_view,
        "extattrs": {
            "Region": {
                "value": f"{current_aws_region}"
            }
        }
    }
    payload = json.dumps(raw_payload)

    conn.request("POST", "/wapi/v2.7/networkcontainer", payload, infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    logger.debug(f"Infoblox new network container request response: {result}")

    # Successful results look like "networkcontainer/ZG5zLm5ldHdvcmtfY29udGFpbmVyJDE5Mi4xNjguMTIuMC8yNC8w:192.168.12.0/24/default"
    if result.startswith("\"networkcontainer") and result.endswith(f'{network_view}\"'):
        logger.info("Successfully created a network container in Infoblox")
        return
    else:
        response = json.loads(result)
        if response["code"] == "Client.Ibap.Data.Conflict":
            logger.warning("This network container already exists in Infoblox. Skipping")
            return
        else:
            raise Exception("Unable to create network container in Infoblox.")

""" 
Description:
Delete list of network containers to Infoblox Grid
 
Keyword arguments:
cidr_block_list -- comma delimited list of cidr blocks representing network containers to delete from the Infoblox Grid for this region
"""
def delete_network_containers(cidr_block_list):
    cidr_block_list = cidr_block_list.replace(" ", "")
    for cidr_block in cidr_block_list.split(","):
        if cidr_block:
            delete_network_container(cidr_block)

""" 
Description:
Deletes single network container from Infoblox Grid
 
Keyword arguments:
cidr_block -- cidr block representing a network container to delete from the Infoblox Grid in this region
"""
def delete_network_container(cidr_block):
    logger.info(f"Deleting network container for {cidr_block} in Infoblox")
    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    payload = f"/wapi/v2.7/networkcontainer?network={cidr_block}&*Region={current_aws_region}&network_view={network_view}"
    conn.request("GET", payload, '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")

    logger.debug(f"All network containers: {result}")

    data = json.loads(result)
    network_containers =[]
    try:
        for entry in data:
            network_containers.append(entry['_ref'])
    except Exception:
        logger.error(f"unexpected response from network container retrieval: {result}")
        raise Exception("unexpected response from network container retrieval")

    logger.info("Network containers associated with this account in this region: ")
    logger.info(network_containers)

    if len(network_containers) > 1:
        raise Exception("Found more than 1 network associated with this cidr in this region")

    if len(network_containers) == 0:
        raise Exception("Found 0 networks associated with this account in this region")

    conn.request("DELETE", "/wapi/v2.7/" + network_containers[0], '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    logger.info(f"Delete request response: {result}")

    # Successful results look like "networkcontainer/ZG5zLm5ldHdvcmtfY29udGFpbmVyJDE5Mi4xNjguMTIuMC8yNC8w:192.168.12.0/24/default"
    if result.startswith("\"networkcontainer") and result.endswith(f'{network_view}\"'):
        logger.info("Successfully deleted a network container from Infoblox")
        return

    raise Exception("Unable to successfully deleted network container from Infoblox.")

""" 
Description:
Setup Extensible Attributes in the Infoblox Grid
"""
def setup_extensible_attributes():
    logger.info("Setting up required extensible attributes in Infoblox")

    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    extensible_attribute_list = ['Region', 'Cloud Account ID', 'Cloudformation Stack ID']

    for attribute in extensible_attribute_list:
        logger.info(f"Setting up attribute '{attribute}' in Infoblox")

        raw_payload = {
            'name': attribute,
            'type': "STRING",
        }
        payload = json.dumps(raw_payload)

        conn.request("POST", "/wapi/v2.7/extensibleattributedef", payload, infoblox_request_header)
        res = conn.getresponse()
        result = res.read().decode("utf-8")
        logger.debug(f"Infoblox new extensible attribute request response: {result}")

        # Successful results look like "extensibleattributedef/b25lLmV4dGVuc2libGVfYXR0cmlidXRlc19kZWYkLkNsb3VkZm9ybWF0aW9uIFN0YWNrIElE:Cloudformation%20Stack%20ID"
        if result.startswith("\"extensibleattributedef"):
            logger.info("Successfully created a extensible attribute in Infoblox")
        else:
            response = json.loads(result)
            if response["code"] == "Client.Ibap.Data.Conflict":
                logger.warning("This extensible attribute already exists in Infoblox. Overwriting attribute instead.")
                overwrite_extensible_attribute(attribute)


            else:
                raise Exception("Unable to create network container in Infoblox.")

""" 
Description:
Overwrites a single Extensible Attribute in the Infoblox Grid

Keyword arguments:
attribute -- name of the string type attribute to overwrite
"""
def overwrite_extensible_attribute(attribute):
    logger.info(f"Overwriting attribute '{attribute}' in Infoblox")

    conn = http.client.HTTPSConnection(infoblox_url, context = ssl._create_unverified_context(), timeout=20)

    payload = f"/wapi/v2.7/extensibleattributedef?name={attribute.replace(' ','+')}"
    conn.request("GET", payload, '', infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    logger.debug(f"Infoblox get extensible attribute request response: {result}")

    data = json.loads(result)
    extensible_attributes =[]
    try:
        for entry in data:
            extensible_attributes.append(entry['_ref'])
    except Exception:
        logger.error(f"unexpected response from extensible attribute retrieval: {result}")
        raise Exception("unexpected response from extensible attribute retrieval")

    logger.info("Extensible attribute found: ")
    logger.info(extensible_attributes)

    if len(extensible_attributes) > 1:
        raise Exception("Found more than 1 extensible attribute")

    if len(extensible_attributes) == 0:
        raise Exception("Found 0 extensible attributes")

    raw_payload = {
        'name': attribute,
        'type': "STRING",
        'allowed_object_types': []
    }
    payload = json.dumps(raw_payload)

    conn.request("PUT", f"/wapi/v2.7/{extensible_attributes[0]}", payload, infoblox_request_header)
    res = conn.getresponse()
    result = res.read().decode("utf-8")
    logger.debug(f"Infoblox overwrite extensible attribute request response: {result}")

    # Successful results look like "extensibleattributedef/b25lLmV4dGVuc2libGVfYXR0cmlidXRlc19kZWYkLkNsb3VkZm9ybWF0aW9uIFN0YWNrIElE:Cloudformation%20Stack%20ID"
    if result.startswith("\"extensibleattributedef"):
        logger.info("Successfully edited a extensible attribute in Infoblox")
    else:
        raise Exception("Unable to edit extensible attribute in Infoblox.")

def lambda_handler(event, context):
    logger.info("Received Event: " + str(event))

    # cloudformation custom resource event from a child account received through SNS topic
    if 'Records' in event:
        for record in event['Records']:
            sns_message = json.loads(record['Sns']['Message'])

            stack_id = sns_message['StackId']
            logger.info(f"Stack ID: {stack_id}")

            # Updating PhysicalResourceId
            s = '%s-%s' % (stack_id, sns_message['LogicalResourceId'])
            physical_resource_id = md5(s.encode('UTF-8')).hexdigest()
            sns_message.update({'PhysicalResourceId': physical_resource_id})
            account_id = stack_id[stack_id.find(current_aws_region+':')+len(current_aws_region+':'):stack_id.rfind(':stack')]
            logger.info(f"Account ID: {account_id}")

            try:
                response_data = None
                if sns_message['RequestType'] == 'Delete':
                    logger.info('Received Delete operation from SNS Message!')
                    del_cidr_block(account_id, stack_id)
                elif sns_message['RequestType'] == 'Update':
                    logger.info('Received Update from SNS Message! No Op!')
                elif sns_message['RequestType'] == 'Create':
                    logger.info('Received Create operation from SNS Message!')
                    new_cidr_block = get_cidr_block(account_id, stack_id)
                    response_data = {'CIDRBlock' : new_cidr_block}
                    num_subnet = 2 # locking to 2 subnets/AZ
                    subnet_list = split_cidr_block(new_cidr_block, num_of_subnet=num_subnet)
                    for i in range(num_subnet):
                        response_data.update({f'Subnet{i+1}' : subnet_list[i]})
                    logger.info(f"ResponseData: {response_data}")
                else:
                    logger.exception("Unexpected contents inside of SNS message. Event should be a cloudformation custom resource event from a child account")
                    raise Exception("Unexpected contents inside of SNS message. Event should be a cloudformation custom resource event from a child account")

                send(sns_message, context, 'SUCCESS', response_data, physical_resource_id)
            except Exception:
                logger.exception('Signaling failure to CloudFormation.')
                send(sns_message, context, 'FAILED', {'status':'Check logs for FAILED details'}, physical_resource_id)

    # Cloudformation custom resource event from central account
    elif 'RequestType' in event:
        try:
            if event['RequestType'] == 'Create':
                logger.info('Received Create operation from custom resource!')
                create_network_containers(event['ResourceProperties']['CIDRBlockList'])
                if event['ResourceProperties']['SetupExtensibleAttributes'] == 'Yes':
                    setup_extensible_attributes()
            elif event['RequestType'] == 'Update':
                logger.info('Received Update operation from custom resource!')
                create_network_containers(event['ResourceProperties']['CIDRBlockList'])
            elif event['RequestType'] == 'Delete':
                logger.info('Received Delete operation from custom resource!')
                delete_network_containers(event['ResourceProperties']['CIDRBlockList'])
            else:
                logger.exception("Unexpected contents inside of custom resource message. Event should be a cloudformation custom resource event from central account")
                raise Exception("Unexpected contents inside of custom resource message. Event should be a cloudformation custom resource event from central account")

            send(event, context, 'SUCCESS')
        except Exception:
            logger.exception('Signaling failure to CloudFormation.')
            send(event, context, 'FAILED', {'status':'Check logs for FAILED details'})

    else:
        logger.exception("Unexpected input to function. Event should either be a cloudformation custom resource event or a SNS message from a child account")
        raise Exception("Unexpected input to function. Event should either be a cloudformation custom resource event or a SNS message from a child account")

    return {
        'statusCode': 200,
        'body': json.dumps('Complete!')
    }

""" 
Description:
Sends a response back to the s3 presigned URL generated by a Cloudformation Custom Resource

Keyword arguments:
event -- base message that the Cloudformation Custom Resource generates
context -- use the current function's lambda context
responseStatus -- Must equal 'SUCCESS' or 'FAILED'
responseData -- Data returned to the Cloudformation Custom Resource
physicalResourceId -- [optional] Used to describe the custom resource ID
noEcho -- [optional] Whether the response body should be traced in Cloudformation Logs
reason -- [optional] Failure reason displayed to the Cloudformation user in the Child Account
"""
def send(event, context, responseStatus, responseData=None, physicalResourceId=None, noEcho=False, reason=None):
  responseUrl = event['ResponseURL']

  logger.info(f"responseUrl: {responseUrl}")

  responseBody = {}
  responseBody['Status'] = responseStatus
  responseBody['Reason'] = reason or "Please create a ticket in APPROPRIATE-TICKET queue and reference CloudWatch Log Stream: {}".format(context.log_stream_name)
  responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
  responseBody['StackId'] = event['StackId']
  responseBody['RequestId'] = event['RequestId']
  responseBody['LogicalResourceId'] = event['LogicalResourceId']
  responseBody['NoEcho'] = noEcho
  responseBody['Data']= responseData or {'status' : 'Check logs for SUCCESS details'}
  logger.info(responseBody['Data'])

  json_response_body = json.dumps(responseBody)

  logger.info("Response body:\n" + json_response_body)

  headers = {
    'content-type' : '',
    'content-length' : str(len(json_response_body))
  }
  try:
    response = pool_manager.request('PUT',responseUrl,headers=headers,body=json_response_body)
    logger.info("Status code: {}".format(str(response.status)))

    if response.status != 200:
        raise Exception(f"Unable to successfully put response to {responseUrl}")
  except Exception as e:
    logger.error("send(..) failed executing requests.put(..): " + str(e))
    raise e