from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'sessions', views.DeepScanSessionViewSet, basename='deepscan-session')
router.register(r'findings', views.DeepScanFindingViewSet, basename='deepscan-finding')
router.register(r'modules', views.ScanModuleViewSet, basename='scan-module')
router.register(r'reports', views.DeepScanReportViewSet, basename='deepscan-report')

urlpatterns = [
    path('', include(router.urls)),
    path('progress/<uuid:session_id>/', views.DeepScanProgressView.as_view(), name='deepscan-progress'),
    path('extension/connect/', views.extension_connect, name='extension-connect'),
    path('actions/record/', views.RecordedActionViewSet.as_view({'post': 'create'}), name='record-action'),
    path('recorded-actions/bulk/', views.BulkRecordedActionView.as_view(), name='bulk-recorded-actions'),
    path('auth/user/', views.get_user_info, name='get-user-info'),
]