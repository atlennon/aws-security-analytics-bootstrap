#!/usr/bin/env python3
from constructs import Construct
from aws_cdk import (
    App, Stack, Aws,
    aws_s3 as s3,
    aws_athena as athena,
    aws_glue as glue
)

from vars import *

class SecurityAnalytics(Stack):

    def __init__(self, scope: App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        QueryOutputLocation = s3.Bucket(self, "QueryOutputLocation")
        cfn_work_group = athena.CfnWorkGroup(self, "SecurityAnalytics",
            name="SecurityAnalytics",
            description="Security Analytics Athena Workgroup",
            recursive_delete_option=True,
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                enforce_work_group_configuration=False,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    selected_engine_version="Athena engine version 2"
                ),
                publish_cloud_watch_metrics_enabled=False,
                requester_pays_enabled=False,
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_S3"
                    ),
                    output_location=f"s3://{QueryOutputLocation.bucket_name}/"
                )
            ),
            work_group_configuration_updates=athena.CfnWorkGroup.WorkGroupConfigurationUpdatesProperty(
                enforce_work_group_configuration=False,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    selected_engine_version="Athena engine version 2"
                ),
                publish_cloud_watch_metrics_enabled=False,
                remove_bytes_scanned_cutoff_per_query=True,
                requester_pays_enabled=False,
                result_configuration_updates=athena.CfnWorkGroup.ResultConfigurationUpdatesProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_S3"
                    ),
                    output_location=f"s3://{QueryOutputLocation.bucket_name}/",
                    remove_encryption_configuration=False,
                    remove_output_location=False
                )
            )
        )

        glue_database = glue.CfnDatabase(self, "GlueDatabase",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                description="Database to hold tables for AWS Service logs",
                name=GlueDatabaseName
            )
        )

        if CloudTrailTableEnabled:
            cloudtrail_table = glue.CfnTable(self, "CloudTrailTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=GlueDatabaseName,
                table_input=glue.CfnTable.TableInputProperty(
                    description="Table for CloudTrail logs",
                    name=CloudTrailTableName,
                    parameters={
                                "classification": "json",
                                "EXTERNAL": "true",
                                "projection.enabled": "true",
                                "projection.date_partition.type": "date",
                                "projection.date_partition.range": f"{CloudTrailProjectionEventStartDate},NOW",
                                "projection.date_partition.format": "yyyy/MM/dd",
                                "projection.date_partition.interval": "1",
                                "projection.date_partition.interval.unit": "DAYS",
                                "projection.region_partition.type": "enum",
                                "projection.region_partition.values": CloudTrailRegionEnum,
                                "projection.account_partition.type": "enum",
                                "projection.account_partition.values": CloudTrailAccountEnum,
                                "storage.location.template": f"{CloudTrailSource}${{account_partition}}/CloudTrail/${{region_partition}}/${{date_partition}}"
                                },
                    partition_keys=[
                        glue.CfnTable.ColumnProperty(
                            name="date_partition",
                            type="string"
                            ),
                        glue.CfnTable.ColumnProperty(
                            name="region_partition",
                            type="string"
                            ),
                        glue.CfnTable.ColumnProperty(
                            name="account_partition",
                            type="string"
                            )
                    ],
                    storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                        columns=[
                            glue.CfnTable.ColumnProperty(
                                name="eventversion",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="useridentity",
                                type="struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="eventtime",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="eventsource",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="awsregion",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sourceipaddress",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="useragent",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="errorcode",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="errormessage",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="requestparameters",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="responseelements",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="additionaleventdata",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="requestid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="eventid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="resources",
                                type="array<struct<ARN:string,accountId:string,type:string>>"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="eventtype",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="apiversion",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="readonly",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="errormessage",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="recipientaccountid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="serviceeventdetails",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sharedeventid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="vpcendpointid",
                                type="string"
                            )
                        ],
                        input_format="com.amazon.emr.cloudtrail.CloudTrailInputFormat",
                        location=CloudTrailSource,
                        output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            parameters={
                                "serialization.format": "1",
                            },
                            serialization_library="com.amazon.emr.hive.serde.CloudTrailSerde"
                        )
                    ),
                    table_type="EXTERNAL_TABLE"
                )
            )

app = App()
SecurityAnalytics(
                    app, "aws-security-analytics-bootstrap",
                    description="Create Athena Bootstrap Infrastructure Resources including default analyst Workgroup and CloudTrail, Flow Log, and DNS Resolver log Tables",
                    env=analytics_region)
app.synth()
