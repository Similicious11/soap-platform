# soap_web/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from security import views

# REST API router
router = DefaultRouter()
router.register(r'scans', views.ScanViewSet)
router.register(r'findings', views.FindingViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Web interface
    path('', views.dashboard, name='dashboard'),
    path('findings/', views.findings_list, name='findings_list'),
    path('scans/', views.scan_history, name='scan_history'),
    
    # REST API
    path('api/', include(router.urls)),
    path('api/stats/', views.dashboard_stats, name='dashboard_stats'),
]
