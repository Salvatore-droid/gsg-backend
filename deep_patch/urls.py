"""
URL configuration for deep_patch project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Schema configuration for API documentation
schema_view = get_schema_view(
    openapi.Info(
        title="DeepPatch Security API",
        default_version='v1',
        description="AI-Powered Security Scanning Platform",
        terms_of_service="https://deeppatch.com/terms/",
        contact=openapi.Contact(email="security@deeppatch.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API Routes
    path('api/', include('base.urls')),
    
    # API Documentation
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # Frontend Routes - Catch all to Vue.js
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
    path('deep-scan/', TemplateView.as_view(template_name='index.html'), name='deep-scan'),
    path('dashboard/', TemplateView.as_view(template_name='index.html'), name='dashboard'),
    
    # Auth routes (if you add authentication)
    path('api/auth/', include('rest_framework.urls')),
]

# Serve static files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_URL)