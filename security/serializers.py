# security/serializers.py
from rest_framework import serializers
from .models import Scan, Finding


class FindingSerializer(serializers.ModelSerializer):
    """Serializer for Finding model"""
    severity_color = serializers.CharField(source='get_severity_color', read_only=True)
    severity_icon = serializers.CharField(source='get_severity_icon', read_only=True)
    
    class Meta:
        model = Finding
        fields = [
            'id', 'scan_id', 'timestamp', 'severity', 'severity_color', 
            'severity_icon', 'category', 'resource_type', 'resource_name',
            'title', 'description', 'recommendation', 'risk_score'
        ]


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model"""
    findings_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'timestamp', 'total_findings', 'critical_count',
            'high_count', 'medium_count', 'low_count', 'duration_seconds',
            'findings_count'
        ]
    
    def get_findings_count(self, obj):
        return obj.findings.count()
