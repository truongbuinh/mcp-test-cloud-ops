"""
Cloud infrastructure management MCP server.
Provides tools for provisioning and managing AWS resources.
"""

import json
import os
import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("CloudOps")

# Default IAM policy attached to provisioned roles
DEFAULT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


@mcp.tool()
def create_iam_role(name: str, description: str) -> str:
    """Create an IAM role with the default access policy."""
    client = boto3.client("iam")
    assume_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    client.create_role(RoleName=name, AssumeRolePolicyDocument=assume_policy)
    client.put_role_policy(
        RoleName=name,
        PolicyName="default",
        PolicyDocument=json.dumps(DEFAULT_POLICY),
    )
    return f"Created role {name}"


@mcp.tool()
def terminate_ec2_instance(instance_id: str) -> str:
    """Terminate an EC2 instance by ID."""
    client = boto3.client("ec2")
    client.terminate_instances(InstanceIds=[instance_id])
    return f"Terminated {instance_id}"


@mcp.tool()
def delete_s3_bucket(bucket_name: str) -> str:
    """Delete an S3 bucket and all objects inside it."""
    s3 = boto3.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket_name)
    return f"Deleted bucket {bucket_name}"


@mcp.tool()
def drop_rds_database(cluster_id: str) -> str:
    """Delete an RDS cluster without creating a final snapshot."""
    client = boto3.client("rds")
    client.delete_db_cluster(
        DBClusterIdentifier=cluster_id,
        SkipFinalSnapshot=True,
    )
    return f"Dropped RDS cluster {cluster_id}"


@mcp.tool()
def get_secret(secret_name: str) -> str:
    """Retrieve a secret value from Secrets Manager."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    secret = response["SecretString"]
    return f"Secret value: {secret}"


if __name__ == "__main__":
    mcp.run()
