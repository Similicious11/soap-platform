# security/models.py
from django.db import models


class Scan(models.Model):
    """Represents a security scan"""
    timestamp = models.DateTimeField()
    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        db_table = 'scans'
        ordering = ['-timestamp']

    def __str__(self):
        return f"Scan #{self.id} - {self.timestamp}"


class Finding(models.Model):
    """Represents a security finding"""
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    timestamp = models.DateTimeField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=50)
    resource_type = models.CharField(max_length=100)
    resource_name = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.TextField()
    recommendation = models.TextField()
    risk_score = models.IntegerField()

    class Meta:
        db_table = 'findings'
        ordering = ['-risk_score', '-timestamp']

    def __str__(self):
        return f"{self.severity}: {self.title}"
    
    def get_severity_color(self):
        """Return color code for severity level"""
        colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        return colors.get(self.severity, '#6c757d')
    
    def get_severity_icon(self):
        """Return emoji icon for severity level"""
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        return icons.get(self.severity, '⚪')
