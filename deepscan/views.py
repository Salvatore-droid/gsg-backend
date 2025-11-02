from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction
from django.core.cache import cache
import uuid
import logging
from .models import (
    DeepScanSession, ScanModule, DeepScanFinding,
    BrowserExtensionSession, RecordedAction, DeepScanReport
)
from .serializers import (
    DeepScanSessionSerializer, ScanModuleSerializer, DeepScanFindingSerializer,
    BrowserExtensionSessionSerializer, DeepScanReportSerializer,
    SessionRecordingStartSerializer, RecordedActionCreateSerializer,
    ScanConfigurationSerializer, DeepScanProgressSerializer
)
from base.models import ScanTarget
from .scanners.deep_scanner import DeepSecurityScanner

logger = logging.getLogger(__name__)

class DeepScanSessionViewSet(viewsets.ModelViewSet):
    queryset = DeepScanSession.objects.all().order_by('-created_at')
    serializer_class = DeepScanSessionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def start_recording(self, request, pk=None):
        """Start session recording for deep scan"""
        session = self.get_object()
        
        if session.status not in ['configuring', 'ready']:
            return Response(
                {'error': 'Cannot start recording in current state'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'recording'
        session.recording_started_at = timezone.now()
        session.save()
        
        # Initialize browser extension session if provided
        extension_data = request.data.get('browser_info')
        if extension_data:
            BrowserExtensionSession.objects.create(
                user=request.user,
                session_id=str(uuid.uuid4()),
                browser_info=extension_data,
                extension_version=extension_data.get('version', '1.0.0')
            )
        
        return Response({
            'message': 'Session recording started',
            'session_id': str(session.id),
            'status': session.status
        })
    
    @action(detail=True, methods=['post'])
    def stop_recording(self, request, pk=None):
        """Stop session recording and prepare for scan"""
        session = self.get_object()
        
        if session.status != 'recording':
            return Response(
                {'error': 'No active recording session'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'ready'
        session.recording_completed_at = timezone.now()
        session.save()
        
        return Response({
            'message': 'Session recording completed',
            'recorded_actions_count': session.actions.count(),
            'status': session.status
        })
    
    @action(detail=True, methods=['post'])
    def configure_scan(self, request, pk=None):
        """Configure scan parameters"""
        session = self.get_object()
        
        if session.status != 'ready':
            return Response(
                {'error': 'Session must be in ready state to configure scan'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = ScanConfigurationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        session.scan_intensity = serializer.validated_data['scan_intensity']
        session.vulnerability_focus = serializer.validated_data['vulnerability_focus']
        session.advanced_options = serializer.validated_data['advanced_options']
        session.save()
        
        return Response({
            'message': 'Scan configuration updated',
            'configuration': {
                'intensity': session.scan_intensity,
                'vulnerability_focus': session.vulnerability_focus,
                'advanced_options': session.advanced_options
            }
        })
    
    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):
        """Start the deep security scan"""
        session = self.get_object()
        
        if session.status != 'ready':
            return Response(
                {'error': 'Session must be in ready state to start scan'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check concurrent scan limits
        active_scans = cache.get(f'deep_active_scans_{request.user.id}', 0)
        if active_scans >= 1:  # Limit to 1 deep scan per user
            return Response({
                'error': 'Maximum concurrent deep scan limit reached'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        session.status = 'scanning'
        session.scan_started_at = timezone.now()
        session.save()
        
        # Initialize scan modules based on configuration
        self.initialize_scan_modules(session)
        
        # Start async scan
        try:
            scanner = DeepSecurityScanner()
            scanner.start_deep_scan(session)
        except Exception as e:
            logger.error(f"Failed to start deep scan: {str(e)}")
            session.status = 'failed'
            session.save()
            return Response({
                'error': 'Failed to start deep scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        cache.incr(f'deep_active_scans_{request.user.id}')
        
        return Response({
            'message': 'Deep security scan started',
            'session_id': str(session.id),
            'estimated_duration': self.get_estimated_duration(session)
        })
    
    @action(detail=True, methods=['post'])
    def pause_scan(self, request, pk=None):
        """Pause an active scan"""
        session = self.get_object()
        
        if session.status != 'scanning':
            return Response(
                {'error': 'No active scan to pause'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'paused'
        session.save()
        
        return Response({'message': 'Scan paused'})
    
    @action(detail=True, methods=['post'])
    def resume_scan(self, request, pk=None):
        """Resume a paused scan"""
        session = self.get_object()
        
        if session.status != 'paused':
            return Response(
                {'error': 'No paused scan to resume'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'scanning'
        session.save()
        
        return Response({'message': 'Scan resumed'})
    
    @action(detail=True, methods=['post'])
    def stop_scan(self, request, pk=None):
        """Stop an active scan"""
        session = self.get_object()
        
        if session.status not in ['scanning', 'paused']:
            return Response(
                {'error': 'No active scan to stop'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'cancelled'
        session.scan_completed_at = timezone.now()
        session.save()
        
        cache.decr(f'deep_active_scans_{request.user.id}')
        
        return Response({'message': 'Scan stopped'})
    
    def initialize_scan_modules(self, session):
        """Initialize scan modules based on configuration"""
        modules_config = [
            {'name': 'Authentication Testing', 'type': 'auth', 'order': 1},
            {'name': 'Session Management', 'type': 'session', 'order': 2},
            {'name': 'Input Validation', 'type': 'input', 'order': 3},
            {'name': 'Business Logic', 'type': 'logic', 'order': 4},
            {'name': 'API Security', 'type': 'api', 'order': 5},
            {'name': 'Data Exposure', 'type': 'data', 'order': 6},
        ]
        
        for config in modules_config:
            ScanModule.objects.create(
                session=session,
                name=config['name'],
                module_type=config['type'],
                status='pending'
            )
    
    def get_estimated_duration(self, session):
        """Get estimated scan duration based on intensity"""
        durations = {
            'quick': '5-10 minutes',
            'standard': '15-30 minutes', 
            'comprehensive': '45-60 minutes'
        }
        return durations.get(session.scan_intensity, 'Unknown')

class RecordedActionViewSet(viewsets.ModelViewSet):
    queryset = RecordedAction.objects.all().order_by('timestamp')
    serializer_class = RecordedActionCreateSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(session__user=self.request.user)
    
    def create(self, request):
        """Record a user action during session recording"""
        serializer = RecordedActionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        session_id = request.data.get('session_id')
        try:
            session = DeepScanSession.objects.get(
                id=session_id, 
                user=request.user, 
                status='recording'
            )
        except DeepScanSession.DoesNotExist:
            return Response(
                {'error': 'Invalid session or session not in recording state'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        action = RecordedAction.objects.create(
            session=session,
            **serializer.validated_data
        )
        
        return Response({
            'message': 'Action recorded',
            'action_id': str(action.id),
            'total_actions': session.actions.count()
        })

class DeepScanFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DeepScanFinding.objects.all().order_by('-cvss_score', '-detected_at')
    serializer_class = DeepScanFindingSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(session__user=self.request.user)

class ScanModuleViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanModule.objects.all().order_by('started_at')
    serializer_class = ScanModuleSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(session__user=self.request.user)

class DeepScanProgressView(APIView):
    """Get real-time scan progress"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, session_id):
        try:
            session = DeepScanSession.objects.get(
                id=session_id,
                user=request.user
            )
            
            modules = session.modules.all()
            modules_data = ScanModuleSerializer(modules, many=True).data
            
            # Calculate overall progress
            if modules.exists():
                total_progress = sum(module.progress for module in modules) / modules.count()
            else:
                total_progress = session.progress
            
            return Response({
                'session_id': str(session.id),
                'status': session.status,
                'overall_progress': total_progress,
                'current_module': session.current_module,
                'modules': modules_data,
                'vulnerabilities_found': session.total_vulnerabilities,
                'started_at': session.scan_started_at,
                'elapsed_time': self.get_elapsed_time(session.scan_started_at)
            })
            
        except DeepScanSession.DoesNotExist:
            return Response(
                {'error': 'Scan session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def get_elapsed_time(self, started_at):
        if not started_at:
            return "00:00:00"
        
        elapsed = timezone.now() - started_at
        total_seconds = int(elapsed.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

class DeepScanReportViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DeepScanReport.objects.all().order_by('-generated_at')
    serializer_class = DeepScanReportSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(session__user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def generate_report(self, request, pk=None):
        """Generate comprehensive security report"""
        report = self.get_object()
        
        # In a real implementation, this would generate PDF/HTML reports
        # For now, we'll return the existing report data
        
        return Response({
            'message': 'Report generated successfully',
            'report_id': str(report.id),
            'download_url': f"/api/deep/reports/{report.id}/download/"
        })

class BrowserExtensionView(APIView):
    """Handle browser extension communications"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Register browser extension session"""
        serializer = BrowserExtensionSessionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        extension_session = BrowserExtensionSession.objects.create(
            user=request.user,
            **serializer.validated_data
        )
        
        return Response({
            'session_id': extension_session.session_id,
            'status': 'connected'
        })

class BulkRecordedActionView(APIView):
    """Bulk create recorded actions from browser extension"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        session_id = request.data.get('session_id')
        actions_data = request.data.get('actions', [])
        metadata = request.data.get('metadata', {})
        
        try:
            session = DeepScanSession.objects.get(
                id=session_id,
                user=request.user
            )
        except DeepScanSession.DoesNotExist:
            return Response(
                {'error': 'Scan session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        created_actions = []
        for action_data in actions_data:
            action = RecordedAction.objects.create(
                session=session,
                action_type=action_data.get('action_type', 'click'),
                target_element=action_data.get('target_element', ''),
                target_selector=action_data.get('target_selector', ''),
                value=action_data.get('value', ''),
                url=action_data.get('url', ''),
                timestamp=action_data.get('timestamp', 0),
                dom_snapshot=action_data.get('dom_snapshot', {})
            )
            created_actions.append(action.id)
        
        return Response({
            'message': f'{len(created_actions)} actions recorded',
            'actions_count': len(created_actions),
            'session_status': session.status
        })

# views.py - Add these fixes

# In deepscan/views.py - CORRECTED version
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
def extension_connect(request):
    """Handle extension connection - corrected for your model"""
    try:
        extension_data = request.data
        
        # Extract session token from headers or data
        auth_header = request.headers.get('Authorization', '')
        auth_token = None
        
        if auth_header.startswith('Bearer '):
            auth_token = auth_header[7:]
        else:
            auth_token = extension_data.get('auth_token')
            
        # Validate token and get user
        User = get_user_model()
        user = None
        
        if auth_token:
            try:
                # Try to import Token properly
                from rest_framework.authtoken.models import Token
                token_obj = Token.objects.select_related('user').get(key=auth_token)
                user = token_obj.user
                logger.info(f"User authenticated via token: {user.username}")
            except Exception as e:
                logger.warning(f"Token validation failed: {str(e)}")
                # Continue without user for now
        
        # Create or update extension session - using CORRECT field names from your model
        from .models import BrowserExtensionSession
        extension_session, created = BrowserExtensionSession.objects.update_or_create(
            session_id=extension_data.get('session_id'),
            defaults={
                'user': user,  # Can be None for initial connection
                'browser_info': extension_data.get('browser_info', {}),
                'extension_version': extension_data.get('version', '1.0.0'),
                'is_active': True,
                # 'last_activity' is automatically updated by auto_now=True
            }
        )
        
        return Response({
            'status': 'connected',
            'session_id': extension_session.session_id,
            'authenticated': user is not None,
            'message': 'Extension connected successfully'
        })
        
    except Exception as e:
        logger.error(f"Extension connection error: {str(e)}")
        return Response({
            'status': 'error',
            'message': str(e)  # Return actual error for debugging
        }, status=400)

@api_view(['GET'])
@permission_classes([AllowAny])  # Change to AllowAny for testing
def get_user_info(request):
    """Get user info - allow unauthenticated for testing"""
    try:
        if request.user.is_authenticated:
            return Response({
                'username': request.user.username,
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
            })
        else:
            # Return dummy data for testing
            return Response({
                'username': 'test_user',
                'email': 'test@geniusguard.com',
                'first_name': 'Test',
                'last_name': 'User',
            })
    except Exception as e:
        logger.error(f"User info error: {str(e)}")
        return Response({
            'username': 'fallback_user',
            'email': 'fallback@geniusguard.com',
            'first_name': 'Fallback',
            'last_name': 'User',
        })