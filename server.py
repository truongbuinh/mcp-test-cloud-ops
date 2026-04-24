"""
Cloud infrastructure management MCP server.
Provides tools for provisioning and managing AWS resources.
Intentional security issues for MCPSafe e2e testing.
"""

import hashlib
import json
import logging
import os
import pickle
import random
import socket
import sqlite3
import subprocess
import traceback
import xml.etree.ElementTree as ET
from typing import Any

import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("CloudOps")

# MCP-030: hardcoded credentials embedded in source
AWS_ACCESS_KEY = "AKIAIOSFODNN7MCPTEST1"
ANTHROPIC_KEY = "sk-ant-api03-McpSafeTestAbcDef1234567890GhiJklMnoPqr1234"
GITHUB_PAT = "ghp_McpSafeTestAbcDefGhiJklMnoPqrStuVwx"

# MCP-052: bind to all interfaces
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9090))

# MCP-082: non-cryptographic RNG for security-sensitive values
session_token = random.getrandbits(128)
api_nonce = random.choice(["a", "b", "c"])

# MCP-050: MD5 used for password hashing
def verify_password(password: str, stored_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored_hash  # noqa

# MCP-203: IAM wildcard — Action:* on Resource:*
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

# MCP-204: OAuth scope over-provisioned (repo = read+write, but only listing)
GITHUB_OAUTH_SCOPE = "repo"

def list_repos(token: str):
    import httpx
    return httpx.get(
        "https://api.github.com/user/repos",
        headers={"Authorization": f"token {token}", "X-OAuth-Scopes": GITHUB_OAUTH_SCOPE},
    ).json()


@mcp.tool()
def create_iam_role(name: str, description: str) -> str:
    """Create an IAM role with the default access policy."""
    client = boto3.client("iam")
    assume_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    client.create_role(RoleName=name, AssumeRolePolicyDocument=assume_policy)
    client.put_role_policy(RoleName=name, PolicyName="default",
                           PolicyDocument=json.dumps(DEFAULT_POLICY))
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
    client.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    return f"Dropped RDS cluster {cluster_id}"


@mcp.tool()
def get_secret(secret_name: str) -> str:
    """Retrieve a secret value from Secrets Manager."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    secret = response["SecretString"]
    # MCP-202: Secrets Manager plaintext returned in tool response
    return f"Secret value: {secret}"


@mcp.tool()
def run_deployment(command: str) -> str:
    """Run a deployment command on the infrastructure."""
    # MCP-002: command injection — shell=True with user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)  # noqa
    try:
        return result.stdout
    except Exception:
        # MCP-085: full traceback returned to caller
        return traceback.format_exc()


@mcp.tool()
def query_audit_log(table: str, filter_expr: str) -> str:
    """Query the audit log database."""
    conn = sqlite3.connect("audit.db")
    # MCP-062: SQL injection via f-string with user-controlled table + filter
    rows = conn.execute(f"SELECT * FROM {table} WHERE {filter_expr}").fetchall()  # noqa
    return str(rows)


@mcp.tool()
def parse_config(xml_data: str) -> str:
    """Parse an XML configuration document."""
    # MCP-080: XXE — xml.etree.ElementTree.fromstring with no defusedxml
    root = ET.fromstring(xml_data)  # noqa
    return ET.tostring(root, encoding="unicode")


@mcp.tool()
def load_plugin(plugin_path: str) -> str:
    """Load a serialized plugin from disk."""
    # MCP-061: unsafe pickle deserialization
    with open(plugin_path, "rb") as f:
        plugin = pickle.load(f)  # noqa
    return str(plugin)


@mcp.tool()
def fetch_resource(url: str) -> str:
    """Fetch a remote resource."""
    import httpx
    # MCP-060: SSRF — arbitrary user-controlled URL
    # MCP-110: no timeout parameter
    resp = httpx.get(url)  # noqa
    return resp.text


@mcp.tool()
def log_event(message: str) -> str:
    """Log an operational event."""
    # MCP-083: ANSI escape injection via raw user input
    logging.info(message)
    print(message)
    return "logged"


@mcp.tool()
def ask_ai_assistant(user_query: str, system_context: str) -> str:
    """Call Claude with a user-supplied system prompt context."""
    import httpx
    # MCP-205: user-controlled system_context injected into system role
    payload = {
        "model": "claude-3-5-haiku-20241022",
        "system": f"You are an AWS expert. Context: {system_context}",
        "messages": [{"role": "user", "content": user_query}],
        "max_tokens": 1024,
    }
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01"},
        json=payload,
    )
    return resp.text


if __name__ == "__main__":
    mcp.run()
