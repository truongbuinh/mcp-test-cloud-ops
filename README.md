# mcp-test-cloud-ops

A cloud infrastructure management MCP server for AWS operations.

## Tools

- `create_iam_role(name, description)` — provision an IAM role
- `terminate_ec2_instance(instance_id)` — stop and terminate an EC2 instance
- `delete_s3_bucket(bucket_name)` — delete a bucket and all its objects
- `drop_rds_database(cluster_id)` — delete an RDS cluster
- `get_secret(secret_name)` — retrieve a value from Secrets Manager

## Usage

```bash
pip install -r requirements.txt
python server.py
```
