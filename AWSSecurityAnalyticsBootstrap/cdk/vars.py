
analytics_region={'region': 'us-west-2'} #Region to deploy Athena analytics workspace
SecurityAnalyticsGlueDatabaseName='security_analytics' #Name of the Glue database to create, which will contain all security analytics tables created by this template (**cannot contain hyphen**)

# CloudTrail Table Parameters
CloudTrailTableEnabled=True #Set to True to create and enable a table for CloudTrail
CloudTrailTableName='cloudtrail' #Name of the cloudtrail Glue table to create
CloudTrailSource='s3://<bucket>/<prefix>/AWSLogs/' #S3 base path of CloudTrail logs to be included in the CloudTrail table (must end with /AWSLogs/ or /AWSLogs/<your_org_id>/ if you're using an organization trail)
CloudTrailProjectionEventStartDate='<YYYY>/<MM>/<DD>' #Start date for CloudTrail logs (replace <YYYY>/<MM>/<DD> with the first date of your logs, example: 2020/11/30)
CloudTrailAccountEnum='<account_num_1>,<account_num_2>,...' #Account(s) to include in the CloudTrail log table in a comma separated list with NO SPACES (example: "0123456789,0123456788,0123456777"); note that all accounts must be logging to the same source, with contents in {ParamVPCFlowSource}/AWSLogs/{account_number}/CloudTrail
CloudTrailRegionEnum='us-east-1,us-east-2,us-west-1,us-west-2,af-south-1,ap-east-1,ap-south-1,ap-northeast-3,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,eu-west-1,eu-west-2,eu-south-1,eu-west-3,eu-north-1,me-south-1,sa-east-1' #Regions to include in the CloudTrail log table in a comma separated list with NO SPACES; Include all regions for full coverage even if there are no logs currently in that region

# VPC Flow Log Table Parameters
VPCFlowTableEnabled=True #'Set to True to create and enable a table for VPC Flow Logs
VPCFlowTableName='vpcflow' #'Name of the VPC flow log Glue table to create
VPCFlowSource='s3://<bucket>/<prefix>/AWSLogs/' #S3 base path of VPC flow logs to be included in the VPC flow table (must end with /AWSLogs/)
VPCFlowProjectionEventStartDate='<YYYY>/<MM>/<DD>' #Start date for VPC flow logs (replace <YYYY>/<MM>/<DD> with the first date of your logs, example: 2020/11/30)
VPCFlowAccountEnum='<account_num_1>,<account_num_2>,...' #Account(s) to include in the VPC flow log table in a comma separated list with NO SPACES (example: "0123456789,0123456788,0123456777"); note that all accounts must be logging to the same source, with contents in {VPCFlowSource}/AWSLogs/{account_number}/vpcflowlogs/'
VPCFlowRegionEnum='us-east-1,us-east-2,us-west-1,us-west-2,af-south-1,ap-east-1,ap-south-1,ap-northeast-3,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,eu-west-1,eu-west-2,eu-south-1,eu-west-3,eu-north-1,me-south-1,sa-east-1' #Regions to include in the VPC flow log table in a comma separated list with NO SPACES; Include all regions for full coverage even if there are no logs currently in that region

# DNS Resolver Log Table Parameters
DNSResolverTableEnabled=True #Set to True to create and enable a table for Route53 DNS Resolver Logs'
DNSResolverTableName='r53dns' #Name of the Route53 DNS Resolver log Glue table to create
DNSResolverSource='s3://<bucket>/<prefix>/AWSLogs/' #S3 base path of Route53 DNS Resolver logs to be included in the Route53 DNS Resolver table (must end with /AWSLogs/)'
DNSResolverProjectionEventStartDate='<YYYY>/<MM>/<DD>' #Start date for Route53 DNS Resolver logs (replace <YYYY>/<MM>/<DD> with the first date of your logs, example: 2020/11/30)'
DNSResolverAccountEnum='<account_num_1>,<account_num_2>,...' #Account(s) to include in the Route53 DNS Resolver log table in a comma separated list with NO SPACES (example: "0123456789,0123456788,0123456777"); note that all accounts must be logging to the same source, with contents in {DNSResolverSource}/AWSLogs/{account_number}/vpcdnsquerylogs/
DNSResolverVPCEnum='<vpc_id_1>,<vpc_id_2>,...' #'VPC IDs to include in the Route53 DNS Resolver log table in a comma separated list with NO SPACES; Include all VPC IDs for full coverage even if there are no logs currently in that VPC

# ALB Table Parameters
ALBTableEnabled=True #Set to True to create and enable a table for ALB logs
ALBRegion='us-east-1' #Region where ALB logs are stored
ALBTableName='alb' #'Name of the ALB Glue table to create
ALBSource='s3://<bucket>/<prefix>/AWSLogs/' #S3 bucket path where logs are stored (including any custom prefix) with NO SPACES (must end with /AWSLogs/) and be located in the region specified in ALBRegion
ALBProjectionEventStartDate='<YYYY>/<MM>/<DD>' #Start date for ALB logs (replace <YYYY>/<MM>/<DD> with the first date of your logs, example: 2020/11/30)'
ALBAccountEnum='<account_num_1>,<account_num_2>,...'#Account(s) to include in the ALB log table in a comma separated list with NO SPACES (example: "0123456789,0123456788,0123456777"); note that all accounts must be logging to the same source, with contents in {ALBSource}/AWSLogs/{account_number}/ALB

# ELB Table Parameters
ELBTableEnabled=True #Set to True to create and enable a table for ELB logs
ELBRegion='us-east-1' #Region where ELB logs are stored
ELBTableName='elb' #'Name of the ELB Glue table to create
ELBSource='s3://<bucket>/<prefix>/AWSLogs/' #S3 bucket path where logs are stored (including any custom prefix) with NO SPACES (must end with /AWSLogs/) and be located in the region specified in ELBRegion
ELBProjectionEventStartDate='<YYYY>/<MM>/<DD>' #Start date for ELB logs (replace <YYYY>/<MM>/<DD> with the first date of your logs, example: 2020/11/30)'
ELBAccountEnum='<account_num_1>,<account_num_2>,...'#Account(s) to include in the ELB log table in a comma separated list with NO SPACES (example: "0123456789,0123456788,0123456777"); note that all accounts must be logging to the same source, with contents in {ELBSource}/AWSLogs/{account_number}/ELB

# IAM Roles Parameters
DeployIamRoles=True #Set to True to deploy IAM roles that can bue used to access Athena workspace and associated logs
LogSourceLocations='bucket_name/prefix/AWSLogs/,bucket_name2/prefix2/AWSLogs/' # Can be retrieved from other vars #"Full path(s) for logs Athena will query in the form '<bucket_name>/<optional_prefix>/AWSLogs/' (comma seperated, no spaces between values)"
QueryOutputLocation='query_history_bucket/optional_prefix/' #bucket is dynamically created by CDK can ref output object # "Full path for Athena output in the form '<bucket_name>/<optional_prefix>/'"
ParamAllBucketNames='log_bucket_1,log_bucket_2,output_bucket' #'The name of all buckets, including log buckets and Athena output bucket (comma seperated, no spaces between values)'