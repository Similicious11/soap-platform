# security/views.py
from django.shortcuts import render
from django.db.models import Count, Q
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Scan, Finding
from .serializers import ScanSerializer, FindingSerializer


def dashboard(request):
    """Main dashboard view"""
    # Get latest scan
    latest_scan = Scan.objects.first()
    
    # Get all findings
    findings = Finding.objects.all()
    
    # Calculate statistics
    severity_stats = findings.values('severity').annotate(count=Count('severity'))
    category_stats = findings.values('category').annotate(count=Count('category'))
    
    # Get recent scans
    recent_scans = Scan.objects.all()[:10]
    
    context = {
        'latest_scan': latest_scan,
        'findings': findings[:20],  # Top 20 findings
        'severity_stats': severity_stats,
        'category_stats': category_stats,
        'recent_scans': recent_scans,
        'total_findings': findings.count(),
    }
    
    return render(request, 'security/dashboard.html', context)


def findings_list(request):
    """Detailed findings list view"""
    findings = Finding.objects.all()
    
    # Filter by severity if requested
    severity_filter = request.GET.get('severity')
    if severity_filter:
        findings = findings.filter(severity=severity_filter)
    
    # Filter by category if requested
    category_filter = request.GET.get('category')
    if category_filter:
        findings = findings.filter(category=category_filter)
    
    context = {
        'findings': findings,
        'severity_filter': severity_filter,
        'category_filter': category_filter,
    }
    
    return render(request, 'security/findings_list.html', context)


def scan_history(request):
    """Scan history view"""
    scans = Scan.objects.all()
    
    context = {
        'scans': scans,
    }
    
    return render(request, 'security/scan_history.html', context)


# REST API ViewSets
class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for scans"""
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for findings"""
    queryset = Finding.objects.all()
    serializer_class = FindingSerializer
    
    def get_queryset(self):
        """Allow filtering by severity and category"""
        queryset = Finding.objects.all()
        
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category=category)
        
        return queryset


@api_view(['GET'])
def dashboard_stats(request):
    """API endpoint for dashboard statistics"""
    latest_scan = Scan.objects.first()
    
    findings = Finding.objects.all()
    
    severity_breakdown = {
        'critical': findings.filter(severity='CRITICAL').count(),
        'high': findings.filter(severity='HIGH').count(),
        'medium': findings.filter(severity='MEDIUM').count(),
        'low': findings.filter(severity='LOW').count(),
    }
    
    category_breakdown = {}
    for category in findings.values_list('category', flat=True).distinct():
        category_breakdown[category] = findings.filter(category=category).count()
    
    data = {
        'latest_scan': {
            'id': latest_scan.id if latest_scan else None,
            'timestamp': latest_scan.timestamp if latest_scan else None,
            'total_findings': latest_scan.total_findings if latest_scan else 0,
        },
        'total_findings': findings.count(),
        'severity_breakdown': severity_breakdown,
        'category_breakdown': category_breakdown,
        'total_scans': Scan.objects.count(),
    }
    
    return Response(data)
