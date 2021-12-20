
# Welcome to the CDK AWS Security Analytics Bootstrap Project

This code can be used to dynamically generate and deploy cloudformation templates for identity and access management using the python programming language. Ideally this should be implemented as part of a pipeline that is triggered automatically by a code merge following a pull request approval.

## Prerequisites

To use this framework you must have the following installed:

`NodeJs` - https://nodejs.org/en/download/  
`AWS CDK` - https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html#getting_started_install  
`AWS Cli` - https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html  
`Git` - https://git-scm.com/downloads  

The install-prerequisites.sh file in the 'AWSSecurityAnalyticsBootstrap/cdk' folder of this repo can be used to install all of these on Amazon linux (Excluding AWS CLI which already comes pre-installed). Make sure to run with sufficent privileges.

Additional information can be found here:

https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html#getting_started_prerequisites

## Initial setup
Once you have the prerequisites you can clone the repo where this code is located, cd into the AWSSecurityAnalyticsBootstrap/cdk directory and complete the following to prepare the enviroment

### Create a virtualenv on MacOS and Linux:
```
$ python3 -m venv .env
```

### Activate your virtualenv
```
$ source .env/bin/activate
```

### Once the virtualenv is activated, you can install the required dependencies.
```
$ pip install -r requirements.txt
```

To add additional dependencies, for example other CDK libraries, just add to
your requirements.txt file and rerun the `pip install -r requirements.txt` command.

### Provide access to AWS

You need to ensure the AWS CLI has access to AWS. Ideally this access is granted using a role assigned to AWS CodeBuild or to an EC2 instance via an instance profile. For testing you can configure the AWS CLI using the aws configure command or set environment variables however this is not recommended for production. Also ensure this account is only granted least permissive access.  

### Bootstrap the CDK

You need to bootstrap the CDK before you can use it to deploy resources to AWS. You can do this by running the command below which deploys a cloudformation stack called `CDKToolkit` that creates an S3 bucket where the CFTs will be uploaded during deployment.

```
$ cdk bootstrap
```

More information on this can be found here: https://docs.aws.amazon.com/cdk/latest/guide/bootstrapping.html  

## Usage Instructions

The modules use functions in the utils.py file to ingest the parameters specified in the vars.py config file and loads them into a list of dictionaries that is then used to dynamically generate the cloudformation for the SsoPermissionSets stack.  

## File Details

 * `vars.py`    Contains all the variables used in the process of generating the cloudformation templates

### Deployment Commands

 * `cdk synth`      Emits synthesized Cft
 * `cdk deploy`     Deploy the specifed in the config file to AWS  
 * `cdk destroy -f` Delete Athena config from AWS (*use with caution!*)

### Important Tips

Make sure to update the variables in the `vars.py` file with the correct values

All cdk commands should be run from the `cdk` directory of the repo