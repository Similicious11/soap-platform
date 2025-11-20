#!/usr/bin/env python3
"""
Security Operations Automation Platform (SOAP)
Core Automation Engine - Weekend Project Version

Author: Your Name
Purpose: ICE Cybersecurity Automation Internship Portfolio Project
"""

import json
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soap_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SOAP')


class SecurityDatabase:
    """Handles all database operations for security findings"""
    
    def __init__(self, db_path: str = 'soap_security.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                duration_seconds REAL
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def create_scan(self) -> int:
        """Create new scan entry and return scan_id"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (timestamp) VALUES (?)
        ''', (datetime.now().isoformat(),))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def add_finding(self, scan_id: int, finding: Dict):
        """Add security finding to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings (
                scan_id, timestamp, severity, category, resource_type,
                resource_name, title, description, recommendation, risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            finding['timestamp'],
            finding['severity'],
            finding['category'],
            finding['resource_type'],
            finding['resource_name'],
            finding['title'],
            finding['description'],
            finding['recommendation'],
            finding['risk_score']
        ))
        
        conn.commit()
        conn.close()
    
    def update_scan_summary(self, scan_id: int, findings: List[Dict], duration: float):
        """Update scan with summary statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        severity_counts = {
            'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in findings if f['severity'] == 'LOW'])
        }
        
        cursor.execute('''
            UPDATE scans SET 
                total_findings = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                duration_seconds = ?
            WHERE id = ?
        ''', (
            len(findings),
            severity_counts['CRITICAL'],
            severity_counts['HIGH'],
            severity_counts['MEDIUM'],
            severity_counts['LOW'],
            duration,
            scan_id
        ))
        
        conn.commit()
        conn.close()


class CloudSecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, config_dir: str = 'mock_cloud_configs'):
        self.config_dir = Path(config_dir)
        self.findings = []
        self.db = SecurityDatabase()
    
    def run_scan(self) -> Tuple[int, List[Dict]]:
        """Execute complete security scan"""
        logger.info("=" * 70)
        logger.info("Starting SOAP Security Scan")
        logger.info("=" * 70)
        
        start_time = datetime.now()
        scan_id = self.db.create_scan()
        logger.info(f"Scan ID: {scan_id}")
        
        # Run all scanner modules
        self.scan_s3_buckets()
        self.scan_security_groups()
        self.scan_iam_policies()
        self.scan_rds_instances()
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        # Store findings in database
        for finding in self.findings:
            self.db.add_finding(scan_id, finding)
        
        # Update scan summary
        self.db.update_scan_summary(scan_id, self.findings, duration)
        
        # Generate report
        self.generate_report(scan_id)
        
        # Print summary
        self.print_summary(duration)
        
        return scan_id, self.findings
    
    def scan_s3_buckets(self):
        """Scan S3 bucket configurations"""
        logger.info("\n[*] Module: S3 Bucket Security Scanner")
        
        config_file = self.config_dir / 's3_buckets.json'
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_file}")
            return
        
        with open(config_file) as f:
            buckets = json.load(f)
        
        for bucket in buckets:
            # Check public access block
            if not bucket.get('public_access_block', {}).get('block_public_acls'):
                self.add_finding(
                    severity='CRITICAL',
                    category='S3_BUCKET',
                    resource_type='AWS::S3::Bucket',
                    resource_name=bucket['name'],
                    title='Public Access Block Disabled',
                    description=f"S3 bucket '{bucket['name']}' does not have Public Access Block enabled, allowing potential public exposure.",
                    recommendation='Enable all Public Access Block settings to prevent accidental public exposure.',
                    risk_score=95
                )
            
            # Check bucket policy
            if bucket.get('bucket_policy', {}).get('allows_public_read'):
                self.add_finding(
                    severity='HIGH',
                    category='S3_BUCKET',
                    resource_type='AWS::S3::Bucket',
                    resource_name=bucket['name'],
                    title='Overly Permissive Bucket Policy',
                    description=f"Bucket '{bucket['name']}' has a policy that allows public read access.",
                    recommendation='Review and restrict bucket policy to authorized principals only.',
                    risk_score=85
                )
            
            # Check encryption
            if not bucket.get('encryption', {}).get('enabled'):
                self.add_finding(
                    severity='MEDIUM',
                    category='S3_BUCKET',
                    resource_type='AWS::S3::Bucket',
                    resource_name=bucket['name'],
                    title='Encryption Not Enabled',
                    description=f"S3 bucket '{bucket['name']}' does not have default encryption enabled.",
                    recommendation='Enable default encryption using AWS KMS or SSE-S3.',
                    risk_score=60
                )
    
    def scan_security_groups(self):
        """Scan EC2 security group rules"""
        logger.info("\n[*] Module: Security Group Scanner")
        
        config_file = self.config_dir / 'security_groups.json'
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_file}")
            return
        
        with open(config_file) as f:
            security_groups = json.load(f)
        
        sensitive_ports = {
            22: 'SSH',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB'
        }
        
        for sg in security_groups:
            for rule in sg.get('ingress_rules', []):
                # Check for 0.0.0.0/0 access
                if rule['source'] == '0.0.0.0/0':
                    port = rule['port']
                    
                    if port in sensitive_ports:
                        self.add_finding(
                            severity='CRITICAL',
                            category='SECURITY_GROUP',
                            resource_type='AWS::EC2::SecurityGroup',
                            resource_name=sg['name'],
                            title=f"Public Access to {sensitive_ports[port]}",
                            description=f"Security group '{sg['name']}' allows unrestricted access (0.0.0.0/0) to {sensitive_ports[port]} on port {port}.",
                            recommendation=f'Restrict access to specific IP ranges or use VPN/bastion host for {sensitive_ports[port]} access.',
                            risk_score=98
                        )
                    elif port == 80 or port == 443:
                        # HTTP/HTTPS public access is usually intentional, lower severity
                        self.add_finding(
                            severity='LOW',
                            category='SECURITY_GROUP',
                            resource_type='AWS::EC2::SecurityGroup',
                            resource_name=sg['name'],
                            title=f"Public Web Access",
                            description=f"Security group '{sg['name']}' allows public access to port {port}. Verify this is intentional.",
                            recommendation='Confirm this public web access is required and properly secured.',
                            risk_score=30
                        )
    
    def scan_iam_policies(self):
        """Scan IAM policy configurations"""
        logger.info("\n[*] Module: IAM Policy Scanner")
        
        config_file = self.config_dir / 'iam_policies.json'
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_file}")
            return
        
        with open(config_file) as f:
            policies = json.load(f)
        
        for policy in policies:
            for statement in policy.get('statements', []):
                # Check for wildcard actions
                if '*' in statement.get('actions', []):
                    self.add_finding(
                        severity='HIGH',
                        category='IAM_POLICY',
                        resource_type='AWS::IAM::Policy',
                        resource_name=policy['name'],
                        title='Overly Permissive IAM Policy',
                        description=f"IAM policy '{policy['name']}' grants wildcard (*) permissions, violating least privilege principle.",
                        recommendation='Replace wildcard permissions with specific required actions.',
                        risk_score=80
                    )
                
                # Check for wildcard resources
                if '*' in statement.get('resources', []):
                    self.add_finding(
                        severity='MEDIUM',
                        category='IAM_POLICY',
                        resource_type='AWS::IAM::Policy',
                        resource_name=policy['name'],
                        title='Wildcard Resource in IAM Policy',
                        description=f"IAM policy '{policy['name']}' applies to all resources (*), increasing blast radius.",
                        recommendation='Scope policy to specific resources using ARNs.',
                        risk_score=65
                    )
    
    def scan_rds_instances(self):
        """Scan RDS database configurations"""
        logger.info("\n[*] Module: RDS Database Scanner")
        
        config_file = self.config_dir / 'rds_instances.json'
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_file}")
            return
        
        with open(config_file) as f:
            instances = json.load(f)
        
        for instance in instances:
            # Check encryption
            if not instance.get('encryption', {}).get('enabled'):
                self.add_finding(
                    severity='HIGH',
                    category='RDS_DATABASE',
                    resource_type='AWS::RDS::DBInstance',
                    resource_name=instance['name'],
                    title='Database Encryption Not Enabled',
                    description=f"RDS instance '{instance['name']}' does not have encryption at rest enabled.",
                    recommendation='Enable encryption at rest using AWS KMS. Note: Requires new instance creation.',
                    risk_score=85
                )
            
            # Check public accessibility
            if instance.get('publicly_accessible'):
                self.add_finding(
                    severity='CRITICAL',
                    category='RDS_DATABASE',
                    resource_type='AWS::RDS::DBInstance',
                    resource_name=instance['name'],
                    title='Publicly Accessible Database',
                    description=f"RDS instance '{instance['name']}' is publicly accessible from the internet.",
                    recommendation='Disable public accessibility and use VPC security groups for access control.',
                    risk_score=95
                )
            
            # Check backup retention
            if instance.get('backup_retention_days', 0) < 7:
                self.add_finding(
                    severity='MEDIUM',
                    category='RDS_DATABASE',
                    resource_type='AWS::RDS::DBInstance',
                    resource_name=instance['name'],
                    title='Insufficient Backup Retention',
                    description=f"RDS instance '{instance['name']}' has backup retention period of {instance.get('backup_retention_days', 0)} days (recommended: 7+ days).",
                    recommendation='Increase backup retention period to at least 7 days for compliance.',
                    risk_score=50
                )
    
    def add_finding(self, severity: str, category: str, resource_type: str,
                   resource_name: str, title: str, description: str,
                   recommendation: str, risk_score: int):
        """Add a security finding"""
        
        severity_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'resource_type': resource_type,
            'resource_name': resource_name,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'risk_score': risk_score
        }
        
        self.findings.append(finding)
        
        # Log the finding
        icon = severity_icons.get(severity, '⚪')
        logger.warning(f"{icon} [{severity}] {category}: {resource_name} - {title}")
    
    def generate_report(self, scan_id: int):
        """Generate JSON report of findings"""
        report = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'findings': self.findings
        }
        
        filename = f"security_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"\n📄 Report saved: {filename}")
    
    def print_summary(self, duration: float):
        """Print scan summary"""
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
        }
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 SCAN SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total Findings: {len(self.findings)}")
        logger.info(f"🔴 CRITICAL: {severity_counts['CRITICAL']}")
        logger.info(f"🟠 HIGH: {severity_counts['HIGH']}")
        logger.info(f"🟡 MEDIUM: {severity_counts['MEDIUM']}")
        logger.info(f"🟢 LOW: {severity_counts['LOW']}")
        logger.info(f"\n⏱️  Scan Duration: {duration:.2f} seconds")
        logger.info("=" * 70)


def main():
    """Main execution function"""
    scanner = CloudSecurityScanner()
    scan_id, findings = scanner.run_scan()
    
    logger.info("\n✅ Scan completed successfully!")
    logger.info(f"💾 Findings stored in database: soap_security.db")
    logger.info(f"📋 View findings: sqlite3 soap_security.db 'SELECT * FROM findings;'")


if __name__ == '__main__':
    main()
