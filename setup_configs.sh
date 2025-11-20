#!/bin/bash
# SOAP Platform - Mock Cloud Configuration Setup
# Creates intentionally misconfigured cloud resources for security scanning

echo "🚀 Setting up SOAP Platform mock cloud environment..."

# Create directory if it doesn't exist
mkdir -p mock_cloud_configs

# Create S3 Buckets Configuration
cat > mock_cloud_configs/s3_buckets.json << 'EOF'
[
  {
    "name": "company-public-website",
    "region": "us-east-1",
    "public_access_block": {
      "block_public_acls": false,
      "block_public_policy": false,
      "ignore_public_acls": false,
      "restrict_public_buckets": false
    },
    "bucket_policy": {
      "allows_public_read": true,
      "statement": "Allow GetObject from *"
    },
    "encryption": {
      "enabled": false
    },
    "versioning": false,
    "logging": false
  },
  {
    "name": "company-backups",
    "region": "us-west-2",
    "public_access_block": {
      "block_public_acls": true,
      "block_public_policy": true,
      "ignore_public_acls": true,
      "restrict_public_buckets": true
    },
    "bucket_policy": {
      "allows_public_read": false
    },
    "encryption": {
      "enabled": false
    },
    "versioning": true,
    "logging": true
  },
  {
    "name": "company-private-data",
    "region": "us-east-1",
    "public_access_block": {
      "block_public_acls": true,
      "block_public_policy": true,
      "ignore_public_acls": true,
      "restrict_public_buckets": true
    },
    "bucket_policy": {
      "allows_public_read": false
    },
    "encryption": {
      "enabled": true,
      "kms_key": "arn:aws:kms:us-east-1:123456789:key/abc-123"
    },
    "versioning": true,
    "logging": true
  }
]
EOF

# Create Security Groups Configuration
cat > mock_cloud_configs/security_groups.json << 'EOF'
[
  {
    "id": "sg-12345",
    "name": "web-server-sg",
    "vpc_id": "vpc-abc123",
    "description": "Security group for web servers",
    "ingress_rules": [
      {
        "port": 80,
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "description": "HTTP from anywhere"
      },
      {
        "port": 443,
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "description": "HTTPS from anywhere"
      }
    ]
  },
  {
    "id": "sg-67890",
    "name": "database-sg",
    "vpc_id": "vpc-abc123",
    "description": "Security group for databases",
    "ingress_rules": [
      {
        "port": 3306,
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "description": "MySQL from anywhere - MISCONFIGURED!"
      }
    ]
  },
  {
    "id": "sg-11111",
    "name": "admin-sg",
    "vpc_id": "vpc-abc123",
    "description": "Administrative access",
    "ingress_rules": [
      {
        "port": 22,
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "description": "SSH from anywhere - INSECURE!"
      },
      {
        "port": 3389,
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "description": "RDP from anywhere - INSECURE!"
      }
    ]
  },
  {
    "id": "sg-22222",
    "name": "app-server-sg",
    "vpc_id": "vpc-abc123",
    "description": "Application servers - Properly configured",
    "ingress_rules": [
      {
        "port": 8080,
        "protocol": "tcp",
        "source": "10.0.0.0/8",
        "description": "App port from internal network"
      }
    ]
  }
]
EOF

# Create IAM Policies Configuration
cat > mock_cloud_configs/iam_policies.json << 'EOF'
[
  {
    "name": "AdminAccessPolicy",
    "arn": "arn:aws:iam::123456789:policy/AdminAccessPolicy",
    "attached_to": ["admin-user", "admin-role"],
    "statements": [
      {
        "effect": "Allow",
        "actions": ["*"],
        "resources": ["*"],
        "condition": null
      }
    ]
  },
  {
    "name": "DeveloperPolicy",
    "arn": "arn:aws:iam::123456789:policy/DeveloperPolicy",
    "attached_to": ["dev-team-role"],
    "statements": [
      {
        "effect": "Allow",
        "actions": [
          "s3:*",
          "ec2:*",
          "rds:*"
        ],
        "resources": ["*"],
        "condition": null
      }
    ]
  },
  {
    "name": "S3ReadOnlyPolicy",
    "arn": "arn:aws:iam::123456789:policy/S3ReadOnlyPolicy",
    "attached_to": ["readonly-user"],
    "statements": [
      {
        "effect": "Allow",
        "actions": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "resources": [
          "arn:aws:s3:::company-backups/*",
          "arn:aws:s3:::company-backups"
        ],
        "condition": null
      }
    ]
  },
  {
    "name": "DataAnalystPolicy",
    "arn": "arn:aws:iam::123456789:policy/DataAnalystPolicy",
    "attached_to": ["analyst-role"],
    "statements": [
      {
        "effect": "Allow",
        "actions": [
          "s3:GetObject",
          "s3:PutObject"
        ],
        "resources": ["*"],
        "condition": null
      }
    ]
  }
]
EOF

# Create RDS Instances Configuration
cat > mock_cloud_configs/rds_instances.json << 'EOF'
[
  {
    "name": "production-db",
    "engine": "mysql",
    "engine_version": "8.0.32",
    "instance_class": "db.t3.medium",
    "region": "us-east-1",
    "publicly_accessible": true,
    "encryption": {
      "enabled": false
    },
    "backup_retention_days": 3,
    "multi_az": false,
    "auto_minor_version_upgrade": true
  },
  {
    "name": "analytics-db",
    "engine": "postgresql",
    "engine_version": "14.7",
    "instance_class": "db.r5.large",
    "region": "us-west-2",
    "publicly_accessible": false,
    "encryption": {
      "enabled": false
    },
    "backup_retention_days": 7,
    "multi_az": true,
    "auto_minor_version_upgrade": true
  },
  {
    "name": "dev-database",
    "engine": "mysql",
    "engine_version": "8.0.32",
    "instance_class": "db.t3.micro",
    "region": "us-east-1",
    "publicly_accessible": false,
    "encryption": {
      "enabled": true,
      "kms_key": "arn:aws:kms:us-east-1:123456789:key/xyz-789"
    },
    "backup_retention_days": 7,
    "multi_az": false,
    "auto_minor_version_upgrade": true
  }
]
EOF

echo ""
echo "✅ Mock cloud environment created successfully!"
echo ""
echo "📁 Files created:"
echo "   - mock_cloud_configs/s3_buckets.json"
echo "   - mock_cloud_configs/security_groups.json"
echo "   - mock_cloud_configs/iam_policies.json"
echo "   - mock_cloud_configs/rds_instances.json"
echo ""
echo "🔍 Configuration Summary:"
echo "   • 3 S3 Buckets (1 public, 1 unencrypted, 1 secure)"
echo "   • 4 Security Groups (2 insecure, 2 properly configured)"
echo "   • 4 IAM Policies (2 overly permissive, 2 least privilege)"
echo "   • 3 RDS Instances (1 public, 2 unencrypted)"
echo ""
echo "🚀 Next step: Run the scanner!"
echo "   python3 cloud_scanner.py"
echo ""
