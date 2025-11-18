from django.urls import path, include
from rest_framework.routers import DefaultRouter
from django.http import JsonResponse
from . import views

router = DefaultRouter()
router.register(r'sessions', views.DeepScanSessionViewSet, basename='deepscan-session')
router.register(r'findings', views.DeepScanFindingViewSet, basename='deepscan-finding')
router.register(r'modules', views.ScanModuleViewSet, basename='scan-module')
router.register(r'reports', views.DeepScanReportViewSet, basename='deepscan-report')

def health_check(request):
    return JsonResponse({'status': 'healthy', 'service': 'deepscan'})

urlpatterns = [
    path('', include(router.urls)),
    path('health/', health_check, name='deepscan-health'),
    path('progress/<uuid:session_id>/', views.DeepScanProgressView.as_view(), name='deepscan-progress'),
    path('extension/connect/', views.extension_connect, name='extension-connect'),
    path('actions/record/', views.RecordedActionViewSet.as_view({'post': 'create'}), name='record-action'),
    path('recorded-actions/bulk/', views.BulkRecordedActionView.as_view(), name='bulk-recorded-actions'),
    path('auth/user/', views.get_user_info, name='get-user-info'),
    
    # Add this fallback user endpoint
    path('user/', views.get_user_info, name='deepscan-user'),
    
    # NEW ENDPOINTS FOR SIMPLIFIED RECORDING FLOW
    path('sessions/start-recording/', views.start_direct_recording, name='start-direct-recording'),
    path('sessions/save-recording/', views.save_recording_session, name='save-recording-session'),
    path('sessions/<uuid:session_id>/recording-status/', views.get_recording_status, name='get-recording-status'),
    
    # Enhanced recording actions endpoint
    path('sessions/<uuid:session_id>/record-actions/', views.record_session_actions, name='record-session-actions'),
]