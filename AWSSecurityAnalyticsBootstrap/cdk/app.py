#!/usr/bin/env python3
import sys
from constructs import Construct
from aws_cdk import (
    App, Stack, Aws, CfnOutput,
    aws_s3 as s3,
    aws_athena as athena,
    aws_glue as glue,
    aws_iam as iam
)

from vars import *

class SecurityAnalytics(Stack):

    def __init__(self, scope: App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        query_output_location = s3.Bucket(self, "QueryOutputLocation")
        security_analytics_workgroup = athena.CfnWorkGroup(self, "SecurityAnalytics",
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
                    output_location=f"s3://{query_output_location.bucket_name}/"
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
                    output_location=f"s3://{query_output_location.bucket_name}/",
                    remove_encryption_configuration=False,
                    remove_output_location=False
                )
            )
        )

        security_analytics_glue_database = glue.CfnDatabase(self, "SecurityAnalyticsGlueDatabase",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                description="Database to hold tables for AWS Service logs",
                name=SecurityAnalyticsGlueDatabaseName
            )
        )

        if CloudTrailTableEnabled:
            cloudtrail_table = glue.CfnTable(self, "CloudTrailTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=SecurityAnalyticsGlueDatabaseName,
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

            cloudtrail_table.add_depends_on(security_analytics_glue_database)

        if VPCFlowTableEnabled:
            vpc_flow_table = glue.CfnTable(self, "VpcFlowTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=SecurityAnalyticsGlueDatabaseName,
                table_input=glue.CfnTable.TableInputProperty(
                    description="Table for VPC flow logs",
                    name=VPCFlowTableName,
                    parameters={
                                "classification": "csv",
                                "EXTERNAL": "true",
                                "skip.header.line.count": "1",
                                "projection.enabled": "true",
                                "projection.date_partition.type": "date",
                                "projection.date_partition.range": f"{VPCFlowProjectionEventStartDate},NOW",
                                "projection.date_partition.format": "yyyy/MM/dd",
                                "projection.date_partition.interval": "1",
                                "projection.date_partition.interval.unit": "DAYS",
                                "projection.region_partition.type": "enum",
                                "projection.region_partition.values": VPCFlowRegionEnum,
                                "projection.account_partition.type": "enum",
                                "projection.account_partition.values": VPCFlowAccountEnum,
                                "storage.location.template": f"{VPCFlowSource}${{account_partition}}/vpcflowlogs/${{region_partition}}/${{date_partition}}"
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
                                name="version",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="account",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="interfaceid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sourceaddress",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="destinationaddress",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sourceport",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="destinationport",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="protocol",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="numpackets",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="numbytes",
                                type="bigint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="starttime",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="endtime",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="action",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="logstatus",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="vpcid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="subnetid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="instanceid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tcpflags",
                                type="smallint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="type",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="pktsrcaddr",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="pktdstaddr",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="region",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="azid",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sublocationtype",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sublocationid",
                                type="smallint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="pkt_src_aws_service",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="pkt_dst_aws_service",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="flow_direction",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="traffic_path",
                                type="string"
                            )
                        ],
                        input_format="org.apache.hadoop.mapred.TextInputFormat",
                        location=VPCFlowSource,
                        output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            parameters={
                                "serialization.format": "",
                                "field.delim": " "
                            },
                            serialization_library="org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                        )
                    ),
                    table_type="EXTERNAL_TABLE"
                )
            )

            vpc_flow_table.add_depends_on(security_analytics_glue_database)

        if DNSResolverTableEnabled:
            dns_resolver_table = glue.CfnTable(self, "DnsResolverTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=SecurityAnalyticsGlueDatabaseName,
                table_input=glue.CfnTable.TableInputProperty(
                    description="Table for DNS Resolver logs",
                    name=DNSResolverTableName,
                    parameters={
                                "classification": "csv",
                                "EXTERNAL": "true",
                                "skip.header.line.count": "1",
                                "projection.enabled": "true",
                                "projection.date_partition.type": "date",
                                "projection.date_partition.range": f"{DNSResolverProjectionEventStartDate},NOW",
                                "projection.date_partition.format": "yyyy/MM/dd",
                                "projection.date_partition.interval": "1",
                                "projection.date_partition.interval.unit": "DAYS",
                                "projection.vpc_partition.type": "enum",
                                "projection.vpc_partition.values": DNSResolverVPCEnum,
                                "projection.account_partition.type": "enum",
                                "projection.account_partition.values": DNSResolverAccountEnum,
                                "storage.location.template": f"{DNSResolverSource}${{account_partition}}/vpcdnsquerylogs/${{vpc_partition}}/${{date_partition}}"
                                },
                    partition_keys=[
                        glue.CfnTable.ColumnProperty(
                            name="date_partition",
                            type="string"
                            ),
                        glue.CfnTable.ColumnProperty(
                            name="vpc_partition",
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
                                name="version",
                                type="float"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="account_id",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="region",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="vpc_id",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="query_timestamp",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="query_name",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="query_type",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="query_class",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="rcode",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="answers",
                                type="array<string>"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="srcaddr",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="srcport",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="transport",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="srcids",
                                type="string"
                            )
                        ],
                        input_format="org.apache.hadoop.mapred.TextInputFormat",
                        location=DNSResolverSource,
                        output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            parameters={
                                "serialization.format": "1"
                            },
                            serialization_library="org.openx.data.jsonserde.JsonSerDe"
                        )
                    ),
                    table_type="EXTERNAL_TABLE"
                )
            )

            dns_resolver_table.add_depends_on(security_analytics_glue_database)

        if ALBTableEnabled:
            alb_table = glue.CfnTable(self, "AlbTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=SecurityAnalyticsGlueDatabaseName,
                table_input=glue.CfnTable.TableInputProperty(
                    description="Table for ALB logs",
                    name=ALBTableName,
                    parameters={
                                "classification": "csv",
                                "EXTERNAL": "true",
                                "skip.header.line.count": "1",
                                "projection.enabled": "true",
                                "projection.date_partition.type": "date",
                                "projection.date_partition.range": f"{ALBProjectionEventStartDate},NOW",
                                "projection.date_partition.format": "yyyy/MM/dd",
                                "projection.date_partition.interval": "1",
                                "projection.date_partition.interval.unit": "DAYS",
                                "projection.account_partition.type": "enum",
                                "projection.account_partition.values": ALBAccountEnum,
                                "storage.location.template": f"{ALBSource}${{account_partition}}/elasticloadbalancing/{ALBRegion}/${{date_partition}}"
                                },
                    partition_keys=[
                        glue.CfnTable.ColumnProperty(
                            name="date_partition",
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
                                name="type",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="time",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="elb",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="client_ip",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="client_port",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_ip",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_port",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="request_processing_time",
                                type="double"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_processing_time",
                                type="double"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="response_processing_time",
                                type="double"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="elb_status_code",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_status_code",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="received_bytes",
                                type="bigint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sent_bytes",
                                type="bigint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="request_verb",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="request_url",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="request_proto",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="user_agent",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="ssl_cipher",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="ssl_protocol",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_group_arn",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="trace_id",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="domain_name",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="chosen_cert_arn",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="matched_rule_priority",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="request_creation_time",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="actions_executed",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="redirect_url",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="lambda_error_reason",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_port_list",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_status_code_list",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="classification",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="classification_reason",
                                type="string"
                            )
                        ],
                        input_format="org.apache.hadoop.mapred.TextInputFormat",
                        location=ALBSource,
                        output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            parameters={
                                "serialization.format": "1",
                                "input.regex": '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\s]+?)\" \"([^\s]+)\" \"([^ ]*)\" \"([^ ]*)\"'
                            },
                            serialization_library="org.apache.hadoop.hive.serde2.RegexSerDe"
                        )
                    ),
                    table_type="EXTERNAL_TABLE"
                )
            )

            alb_table.add_depends_on(security_analytics_glue_database)

        if ELBTableEnabled:
            elb_table = glue.CfnTable(self, "ElbTable",
                catalog_id=Aws.ACCOUNT_ID,
                database_name=SecurityAnalyticsGlueDatabaseName,
                table_input=glue.CfnTable.TableInputProperty(
                    description="Table for ELB logs",
                    name=ELBTableName,
                    parameters={
                                "classification": "csv",
                                "EXTERNAL": "true",
                                "skip.header.line.count": "1",
                                "projection.enabled": "true",
                                "projection.date_partition.type": "date",
                                "projection.date_partition.range": f"{ELBProjectionEventStartDate},NOW",
                                "projection.date_partition.format": "yyyy/MM/dd",
                                "projection.date_partition.interval": "1",
                                "projection.date_partition.interval.unit": "DAYS",
                                "projection.account_partition.type": "enum",
                                "projection.account_partition.values": ELBAccountEnum,
                                "storage.location.template": f"{ELBSource}${{account_partition}}/elasticloadbalancing/{ELBRegion}/${{date_partition}}"
                                },
                    partition_keys=[
                        glue.CfnTable.ColumnProperty(
                            name="date_partition",
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
                                name="type",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="version",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="time",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="elb",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="listener_id",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="client_ip",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="client_port",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_ip",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="target_port",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tcp_connection_time_ms",
                                type="double"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tls_handshake_time_ms",
                                type="double"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="received_bytes",
                                type="bigint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="sent_bytes",
                                type="bigint"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="incoming_tls_alert",
                                type="int"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="cert_arn",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="certificate_serial",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tls_cipher_suite",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tls_protocol_version",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="tls_named_group",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="domain_name",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="alpn_fe_protocol",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="alpn_be_protocol",
                                type="string"
                            ),
                            glue.CfnTable.ColumnProperty(
                                name="alpn_client_preference_list",
                                type="string"
                            )
                        ],
                        input_format="org.apache.hadoop.mapred.TextInputFormat",
                        location=ELBSource,
                        output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            parameters={
                                "serialization.format": "1",
                                "input.regex": '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*):([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-0-9]*) ([-0-9]*) ([-0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*)$'
                            },
                            serialization_library="org.apache.hadoop.hive.serde2.RegexSerDe"
                        )
                    ),
                    table_type="EXTERNAL_TABLE"
                )
            )

            elb_table.add_depends_on(security_analytics_glue_database)

            ResourceDemoQueryCloudTrail1 = athena.CfnNamedQuery(self, "ResourceDemoQueryCloudTrail1",
                database=SecurityAnalyticsGlueDatabaseName,
                query_string="-- preview first 10 rows with all fields, limited by a combination partition constraints \
                            -- NOTE: narrowing the scope of the query as much as possible will improve performance and minimize cost \
                            SELECT * from cloudtrail \
                            WHERE date_partition >= '2021/07/01' \
                            AND date_partition <= '2021/07/31' \
                            AND account_partition = '111122223333' \
                            AND region_partition in ('us-east-1','us-east-2','us-west-1', 'us-west-2') \
                            LIMIT 10;",
                description="preview first 10 rows with all fields, limited by a combination partition constraints",
                name="DEMO_CloudTrail_AllPartitions",
                work_group="SecurityAnalytics"
            )

            ResourceDemoQueryCloudTrail1.add_depends_on(cloudtrail_table)

            # ResourceDemoQueryVPCFlow1 = athena.CfnNamedQuery(self, "ResourceDemoQueryVPCFlow1",
            #     database=SecurityAnalyticsGlueDatabaseName,
            #     query_string="-- preview first 10 rows with all fields, limited by a combination partition constraints \
            #                   -- NOTE: narrowing the scope of the query as much as possible will improve performance and minimize cost \
            #                   SELECT * from vpcflow \
            #                   WHERE date_partition >= '2021/07/01' \
            #                   AND date_partition <= '2021/07/31' \
            #                   AND account_partition = '111122223333' \
            #                   AND region_partition in ('us-east-1','us-east-2','us-west-2', 'us-west-2') \
            #                   LIMIT 10;",
            #     description="preview first 10 rows with all fields, limited by a combination partition constraints",
            #     name="DEMO_VPCFlow_AllPartitions",
            #     work_group="SecurityAnalytics"
            # )

# Deploy Athena Admin and Analyst IAM Roles if option is selected in vars.py file
        if DeployIamRoles:

            if AthenaAnalystAssumeRoleArn == 'ANY':
                athena_analyst_role_assumer=iam.AccountPrincipal(Aws.ACCOUNT_ID)
            elif AthenaAnalystAssumeRoleArn != '':
                athena_analyst_role_assumer = iam.Role.from_role_arn(self, "AthenaAnalystRoleAssumer", role_arn=AthenaAnalystAssumeRoleArn)
            else:
                sys.exit("Error: No value specified for 'AthenaAnalystAssumeRoleArn' please check the vars.py file")

            if AthenaAdminAssumeRoleArn == 'ANY':
                athena_admin_role_assumer=iam.AccountPrincipal(Aws.ACCOUNT_ID)
            elif AthenaAdminAssumeRoleArn != '':
                athena_admin_role_assumer = iam.Role.from_role_arn(self, "AthenaAdminRoleAssumer", role_arn=AthenaAdminAssumeRoleArn)
            else:
                sys.exit("Error: No value specified for 'AthenaAdminAssumeRoleArn' please check the vars.py file")

# Get all log source buckets and add to list
            log_source_buckets=[]
            if CloudTrailTableEnabled:
                log_source_buckets.append(CloudTrailSource[0:CloudTrailSource.find('/',5)])
                log_source_buckets.append(CloudTrailSource[0:CloudTrailSource.find('/',5)]+'/*')
            if VPCFlowTableEnabled:
                log_source_buckets.append(VPCFlowSource[0:VPCFlowSource.find('/',5)])
                log_source_buckets.append(VPCFlowSource[0:VPCFlowSource.find('/',5)]+'/*')
            if DNSResolverTableEnabled:
                log_source_buckets.append(DNSResolverSource[0:DNSResolverSource.find('/',5)])
                log_source_buckets.append(DNSResolverSource[0:DNSResolverSource.find('/',5)]+'/*')
            if ALBTableEnabled:
                log_source_buckets.append(ALBSource[0:ALBSource.find('/',5)])
                log_source_buckets.append(ALBSource[0:ALBSource.find('/',5)]+'/*')
            if ELBTableEnabled:
                log_source_buckets.append(ELBSource[0:ELBSource.find('/',5)])
                log_source_buckets.append(ELBSource[0:ELBSource.find('/',5)]+'/*')

# Athena analyst role
            athena_analyst_role = iam.Role(self, "AthenaAnalystRole",
                role_name="security_analytics_athena_analyst",
                assumed_by=athena_analyst_role_assumer,
                description="Provides analyst access to security analytics athena workspace"
            )

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityNamedQueryFullAccess",
            actions=[
                "athena:BatchGetNamedQuery",
                "athena:CreateNamedQuery",
                "athena:DeleteNamedQuery",
                "athena:GetNamedQuery",
                "athena:ListNamedQueries"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Workgroup resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for Athena Workgroup resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple workgroups.
#       If you only plan to use a single workgroup, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the workgroups you plan to use.
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityWorkgroupReadOnly",
            actions=[
                "athena:GetWorkGroup",
                "athena:ListWorkGroups",
                "athena:BatchGetQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:GetQueryResultsStream",
                "athena:ListQueryExecutions",
                "athena:ListTagsForResource",
                "athena:StartQueryExecution",
                "athena:StopQueryExecution"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Workgroup resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for Athena Workgroup resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple workgroups.
#       If you only plan to use a single workgroup, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the workgroups you plan to use.  
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityAthenaDataCatalogReadOnly",
            actions=[
                "athena:GetDataCatalog",
                "athena:ListDataCatalogs",
                "athena:GetDatabase",
                "athena:ListDatabases",
                "athena:GetTableMetadata",
                "athena:ListTableMetadata"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Data Catalog resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Athena Data Catalog resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple data catalogs.
#       If you only plan to use a single data catalog, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the data catalog you plan to use.  
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGlueDatabaseReadOnly",
            actions=[
                "glue:GetDatabase",
                "glue:GetDatabases"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Database resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Database resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.  
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGlueTableReadOnly",
            actions=[
                "glue:GetTable",
                "glue:GetTables"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Table resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Table resources are associated with a Glue Database that starts with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       Note that Glue Table ARNs are in the format arn:aws:glue:region:account-id:table/database name/table name, so this will allow any table naming scheme as long as it is associated with a Glue Database staringing with 'Security' or 'security_'.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.
#       You may also specify the full Database/Table name explicitly in the ARN if you know would like to limit the actions to only those tables explicitly.
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:table/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:table/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGluePartitionReadOnly",
            actions=[
                "glue:BatchGetPartition",
                "glue:GetPartition",
                "glue:GetPartitions"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Database resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Database resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.  
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/security_*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="AthenaOutputBucketReadWrite",
            actions=[
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:ListMultipartUploadParts",
                "s3:PutObject"
            ],
# Note: The '*' in each resource below is to allow the actions above on all S3 Objects in the specified S3 Bucket.  If you'd like to limit it to a specific path you could for example specify '/athena/*'
            resources=[f"{query_output_location.bucket_arn}*"]
            ))

            athena_analyst_role.add_to_policy(iam.PolicyStatement(
            sid="LogSourceBucketReadOnly",
            actions=[
                "s3:GetObject",
                "s3:GetBucketLocation",
                "s3:ListBucket"
            ],
            resources=log_source_buckets
            ))

            CfnOutput(self, "OutputAthenaSecurityAnalystRoleArn", value=athena_analyst_role.role_arn, description="Athena Analyst Role ARN")

# Athena admin role
            athena_admin_role = iam.Role(self, "AthenaAdminRole",
                role_name="security_analytics_athena_admin",
                assumed_by=athena_admin_role_assumer,
                description="Provides admin access to security analytics athena workspace"
            )

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityNamedQueryFullAccess",
            actions=[
                "athena:BatchGetNamedQuery",
                "athena:CreateNamedQuery",
                "athena:DeleteNamedQuery",
                "athena:GetNamedQuery",
                "athena:ListNamedQueries"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Workgroup resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for Athena Workgroup resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple workgroups.
#       If you only plan to use a single workgroup, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the workgroups you plan to use.
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityWorkgroupFullAccess",
            actions=[
                "athena:CreateWorkGroup",
                "athena:DeleteWorkGroup",
                "athena:GetWorkGroup",
                "athena:ListWorkGroups",
                "athena:UpdateWorkGroup",
                "athena:BatchGetQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:GetQueryResultsStream",
                "athena:ListQueryExecutions",
                "athena:ListTagsForResource",
                "athena:StartQueryExecution",
                "athena:StopQueryExecution"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Workgroup resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for Athena Workgroup resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple workgroups.
#       If you only plan to use a single workgroup, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the workgroups you plan to use.  
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityAthenaDataCatalogFullAccess",
            actions=[
                "athena:CreateDataCatalog",
                "athena:DeleteDataCatalog",
                "athena:GetDataCatalog",
                "athena:ListDataCatalogs",
                "athena:UpdateDataCatalog",
                "athena:GetDatabase",
                "athena:ListDatabases",
                "athena:GetTableMetadata",
                "athena:ListTableMetadata"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Data Catalog resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Athena Data Catalog resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple data catalogs.
#       If you only plan to use a single data catalog, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the data catalog you plan to use.  
            resources=[f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/Security*",f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGlueDatabaseFullAccess",
            actions=[
                "glue:CreateDatabase",
                "glue:DeleteDatabase",
                "glue:GetDatabase",
                "glue:GetDatabases",
                "glue:UpdateDatabase"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Database resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Database resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.  
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGlueTableFullAccess",
            actions=[
                "glue:BatchDeleteTable",
                "glue:CreateTable",
                "glue:DeleteTable",
                "glue:GetTable",
                "glue:GetTables",
                "glue:UpdateTable"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Table resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Table resources are associated with a Glue Database that starts with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       Note that Glue Table ARNs are in the format arn:aws:glue:region:account-id:table/database name/table name, so this will allow any table naming scheme as long as it is associated with a Glue Database staringing with 'Security' or 'security_'.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.
#       You may also specify the full Database/Table name explicitly in the ARN if you know would like to limit the actions to only those tables explicitly.
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:table/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:table/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityGluePartitionReadWrite",
            actions=[
                "glue:BatchCreatePartition",
                "glue:BatchDeletePartition",
                "glue:BatchGetPartition",
                "glue:CreatePartition",
                "glue:DeletePartition",
                "glue:GetPartition",
                "glue:GetPartitions",
                "glue:UpdatePartition"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Glue Database resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for all Glue Database resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple databases.
#       If you only plan to use a single database, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the database you plan to use.  
            resources=[f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/Security*",f"arn:aws:glue:*:{Aws.ACCOUNT_ID}:database/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="SecurityAthenaTagResources",
            actions=[
                "athena:TagResource",
                "athena:UntagResource"
            ],
# Note: The first '*' in each resource below is to allow the actions above for Athena Workgroup resources in all regions, if only one region will be used you may specify the specific region or use ${AWS::Region} to specify the current region
#       The second '*' in each resource below is to allow the actions above for Athena Workgroup resources which start with 'Security' or 'security_' as a standard naming scheme, which allows flexibility if you want to use multiple workgroups.
#       If you only plan to use a single workgroup, you may specify the name here and replace 'Security*' or 'security_' with the explicit name(s) of the workgroups you plan to use. 
            resources=[
                    f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/Security*",
                    f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:workgroup/security_*",
                    f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/security_*",
                    f"arn:aws:athena:*:{Aws.ACCOUNT_ID}:datacatalog/security_*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="AthenaOutputBucketReadWrite",
            actions=[
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:ListMultipartUploadParts",
                "s3:PutObject"
            ],
# Note: The '*' in each resource below is to allow the actions above on all S3 Objects in the specified S3 Bucket.  If you'd like to limit it to a specific path you could for example specify '/athena/*'
            resources=[f"{query_output_location.bucket_arn}*"]
            ))

            athena_admin_role.add_to_policy(iam.PolicyStatement(
            sid="LogSourceBucketReadOnly",
            actions=[
                "s3:GetObject",
                "s3:GetBucketLocation",
                "s3:ListAllMyBuckets",
                "s3:ListBucket"
            ],
            resources=log_source_buckets
            ))

            CfnOutput(self, "OutputAthenaSecurityAdminRoleArn", value=athena_admin_role.role_arn, description="Athena Admin Role ARN")

app = App()
SecurityAnalytics(
                    app, "aws-security-analytics-bootstrap",
                    description="Create Athena Bootstrap Infrastructure Resources including default analyst Workgroup and CloudTrail, Flow Log, and DNS Resolver log Tables",
                    env=analytics_region)
app.synth()
