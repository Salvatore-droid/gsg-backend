"""
URL configuration for base app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'scan-targets', views.ScanTargetViewSet, basename='scan-target')
router.register(r'scan-results', views.ScanResultViewSet, basename='scan-result')
router.register(r'threat-intelligence', views.ThreatIntelligenceViewSet, basename='threat-intelligence')
router.register(r'global-stats', views.GlobalStatsViewSet, basename='global-stats')
router.register(r'quick-scan', views.QuickScanViewSet, basename='quick-scan')

urlpatterns = [
    # API routes
    path('', include(router.urls)),
    
    # Additional custom endpoints
    path('scan-status/<uuid:scan_id>/', views.ScanStatusView.as_view(), name='scan-status'),
    path('vulnerabilities/', views.VulnerabilityListView.as_view(), name='vulnerability-list'),
]