## VPC Service Catalog Product Infoblox IPAM

Large organizations have challenges creating VPCs within their LZ/CT while managing IP address space. Networking 
teams traditionally have no automation to provision new VPCs in each child account while also tracking CIDR blocks 
used. This solution outlines how organizations and service catalog can be leveraged in partnership with Infoblox DDI to 
simplify VPC provisioning with no manual interaction for networking teams. The solution delivers enhanced visibility 
in to the governance of infrastructure at scale while reducing workload and provisioning time for newly vended accounts.

This is a solution that allows customers to create a dedicated VPC in a child account which reaches out to the 
Infoblox IPAM system to allocate the next available CIDR Block for a region.

## Solution Overview

A designated networking account contains a centrally managed transit gateway which is shared to all eligible child 
accounts using AWS RAM.

A designated central account contains a VPC with access to the Infoblox Grid Master. A lambda function is deployed 
to this central account within the VPC to process requests from child accounts that are received through a SNS topic.
This SNS topic has a topic policy that allows any account from the organization to publish messages to this topic. 
The lambda function uses AWS Secrets Manager to store the authorization information used to authenticate calls with 
the Infoblox Grid. The SNS topic and Secrets Manager secret are protected by a customer managed AWS KMS Key. These 
components are deployed using the [VPCSCProductHelper.yml](./VPCSCProductHelper.yml) cloudformation template.

Child accounts throughout the organization access a product that is shared as part of a portfolio using AWS Service 
Catalog. This CloudFormation template named [VPCSCProduct.yml](./VPCSCProduct.yml) creates a

* VPC
* 2 private subnets
* A transit gateway attachment spanning 2 private subnets
* Private subnet route table containing a default route to the TGW
* A lambda function based custom resource which checks that
    * only a single TGW exists in the account
* A custom resource that has a service token referencing the SNS topic in the central account.

If multiple Infoblox network containers are allocated for a single AWS region, the child account will receive the 
CIDR block information of the next available network from a randomly selected free network container.

These elements work in tandem to deliver a seamless experience as new accounts are created throughout your 
organization. Individual account owners can create a VPC that deliver connectivity through your organization’s TGW 
without overlapping CIDR Blocks. This not only reduces the provisioning time for accounts requiring access to VPCs, 
it increases governance and visibility as Infoblox DDI can identify which CIDR blocks have been assigned for an 
account in a region.

![Architecture Diagram for Solution](./documentation/images/VPC%20Product%20Architecture.jpg)

## Setting up AWS Transit Gateway share
1.	Follow the steps listed [here](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-transit-gateways.html#create-tgw) 
      to create a transit gateway according to your organization’s needs.
2.	Follow the steps listed [here](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-transit-gateways.html#tgw-sharing) 
      to share the transit gateway across your organization by specifying an AWS account, OU, or organization

## Setting up Infoblox grid master
Connect to your organization’s existing Infoblox DDI Grid Master (hosted on-prem or in the cloud) to be accessible 
through the VPC located in the central account. If you do not have access to an existing Infoblox appliance, follow 
the steps listed 
[here](https://www.infoblox.com/wp-content/uploads/infoblox-deployment-guide-deploy-infoblox-vnios-instances-for-aws.pdf) 
to deploy a new Infoblox appliance on AWS.

### Setting up required Infoblox extensible attributes
This solution uses 'Cloud Account ID', 'Region', and 'Cloudformation Stack ID' as extensible attributes for IPv4 
networks. 'Region' is used as an extensible attribute for IPv4 Network Containers. Be sure that the 'Restricted 
to Objects' field for these extensible attributes are unrestricted or allow these object types. 

These can be automatically configured by keeping the default parameter of 'Yes' on the 'Setup Infoblox Extensible 
Attribute' parameter. Alternatively, follow the Infoblox guide 
[here](https://docs.infoblox.com/display/nios84/Managing+Extensible+Attributes#ManagingExtensibleAttributes)
to add or edit these manually. 

### Setting up Infoblox network containers
The parent CIDR Block(s) that this solution will create child VPC CIDR Blocks from is contained in the Infoblox 
grid as IPv4 Network Containers that have an extensible attribute of 'Region' with the AWS region (i.e. us-east-1) as 
the value.

These can be automatically configured by supplying a comma delimited list of CIDR Blocks in CIDR notation to the 
'Infoblox Network Containers' parameter. Alternatively, follow the Infoblox guide
[here](https://docs.infoblox.com/display/nios85/Configuring+IPv4+Networks#ConfiguringIPv4Networks-bookmark2343)
to add or modify these manually.

## Central account setup

### Prerequisties
Be sure to have
* provisioned a VPC in this account that contains access to a minimum of 2 private subnets in different availability 
zones that allow connectivity to AWS service endpoints. This can be achieved commonly using NAT Gateways or VPC endpoints.  
* Network interfaces in the subnets should also have a valid network path to the Infoblox NIOS appliance.

### Deploying Cloudformation template

Upload the [zip file](./VPCasSCProductHelper.py.zip) to a S3 bucket in your account. Follow 
[this](https://docs.aws.amazon.com/AmazonS3/latest/user-guide/upload-objects.html) guide to learn more about file 
uploads to S3.

Download the [VPCSCProductHelper.yml](./VPCSCProductHelper.yml) CloudFormation template and create a CloudFormation 
stack. For more information about how to create a CloudFormation stack, see 
[Getting Started with AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.html) 
in the AWS CloudFormation User Guide.

Most of the parameters can be left as default, but some may need to be modified depending on organizational 
preference. The lambda security group may use the default VPC security group if the outbound rules allow traffic to 
the Infoblox appliance. Changing parameters such as the SNS Topic Name may require changes to the corresponding 
template deployed in the service catalog in child accounts.

After you stack has finished deploying, edit the newly created secret in AWS Secrets Manager to replace the text with 
your secure Infoblox password. This password in combination with the username entered as an AWS CloudFormation 
parameter above should be for an account that has been provisioned for use in Infoblox DDI. Follow the Infoblox 
[documentation](https://docs.infoblox.com/display/nios85/Managing+Administrators) for more information about 
required permissions to manage the grid and local authentication/Active Directory users.

## Setting up the AWS Service Catalog product in child accounts
1.	Create a service catalog portfolio in a designated administrator account following the instructions 
      [here](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/portfoliomgmt-create.html)
2.	Download the [VPCSCProduct.yml](./VPCSCProduct.yml) CloudFormation template and follow this 
      [guide](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/portfoliomgmt-products.html) to upload
      the template as a product to the portfolio
3.	Use this [guide](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/portfoliomgmt-constraints.html) 
      to add template constraints that restrict parameters of the product template. This can be used 
      to lock the Central Account ID parameter to one designated for your organization.
4.	Follow this [guide](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/catalogs_portfolios_users.html)
      to grant access to users in this account for testing
5.	Follow this 
      [guide](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/catalogs_portfolios_sharing_how-to-share.html) 
      to share this portfolio to designated AWS accounts within your organization.

## Cleanup
If you no longer require access to this solution
1.	Delete the CloudFormation template deployed in the central account setup section
2.	Delete the S3 Bucket and files uploaded in the central account setup section
3.	Delete the service catalog product and/or portfolio deployed in the service catalog setup section.
4.	Delete the transit gateway in the networking account
5.	Decommission the Infoblox appliance by terminating the EC2 instance if hosted on AWS or removing access to the on-prem grid instance.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

