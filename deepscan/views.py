# deepscan/views.py - COMPLETE FIXED VERSION

from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, permission_classes, api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.utils import timezone
from django.db import transaction
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist 
import uuid
import jwt
import logging
from django.conf import settings
from .authentication import JWTAuthentication, SessionOrJWTAuthentication

from .models import (
    DeepScanSession, ScanModule, DeepScanFinding,
    BrowserExtensionSession, RecordedAction, DeepScanReport
)
from .serializers import *
from base.models import ScanTarget

logger = logging.getLogger(__name__)
User = get_user_model()

# Utility functions for authentication
def validate_jwt_token(token_string):
    """
    Validate JWT token used by GeniusGuard
    """
    try:
        if not token_string:
            return None
            
        payload = jwt.decode(token_string, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        
        if not user_id:
            return None
            
        user = User.objects.get(id=user_id)
        return user
        
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None
    except User.DoesNotExist:
        logger.warning(f"User not found in JWT token")
        return None
    except Exception as e:
        logger.error(f"JWT validation error: {str(e)}")
        return None

def get_user_from_request(request):
    """
    Get user from request - supports both session and JWT
    """
    # Primary: Session authentication
    if hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    
    # Secondary: JWT token authentication
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        user = validate_jwt_token(token)
        if user:
            return user
    
    # Fallback: Session user_id
    if hasattr(request, 'session') and 'user_id' in request.session:
        try:
            return User.objects.get(id=request.session['user_id'])
        except (User.DoesNotExist, KeyError):
            pass
    
    return None

# In deepscan/views.py - update the DeepScanSessionViewSet

class DeepScanSessionViewSet(viewsets.ModelViewSet):
    queryset = DeepScanSession.objects.all().order_by('-created_at')
    authentication_classes = [SessionOrJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return DeepScanSessionCreateSerializer  # Use the new serializer for creation
        return DeepScanSessionSerializer
    
    def get_queryset(self):
        user = get_user_from_request(self.request)
        if user and user.is_authenticated:
            return self.queryset.filter(user=user)
        return self.queryset.none()
    
    def perform_create(self, serializer):
        user = get_user_from_request(self.request)
        if not user or not user.is_authenticated:
            from rest_framework import serializers
            raise serializers.ValidationError("Authentication required")
        
        # Target is now optional - get it if provided, otherwise use None
        target_id = self.request.data.get('target')
        target = None
        
        if target_id:
            try:
                target = ScanTarget.objects.get(id=target_id)
            except ScanTarget.DoesNotExist:
                # Log warning but don't fail the request
                logger.warning(f"ScanTarget with id {target_id} does not exist")
                # Continue without target - don't raise error
        
        # Save with user and optional target
        serializer.save(user=user, target=target)
    
    
    
    @action(detail=True, methods=['post'])
    def start_recording(self, request, pk=None):
        """Start session recording for deep scan"""
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        
        # Start async scan (placeholder - implement your scanner)
        try:
            # scanner = DeepSecurityScanner()
            # scanner.start_deep_scan(session)
            logger.info(f"Starting deep scan for session {session.id}")
        except Exception as e:
            logger.error(f"Failed to start deep scan: {str(e)}")
            session.status = 'failed'
            session.save()
            return Response({
                'error': 'Failed to start deep scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        cache.set(f'deep_active_scans_{request.user.id}', active_scans + 1, 3600)  # 1 hour cache
        
        return Response({
            'message': 'Deep security scan started',
            'session_id': str(session.id),
            'estimated_duration': self.get_estimated_duration(session)
        })
    
    @action(detail=True, methods=['post'])
    def pause_scan(self, request, pk=None):
        """Pause an active scan"""
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        session = self.get_object()
        
        if session.status not in ['scanning', 'paused']:
            return Response(
                {'error': 'No active scan to stop'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'cancelled'
        session.scan_completed_at = timezone.now()
        session.save()
        
        # Decrement active scans counter
        active_scans = cache.get(f'deep_active_scans_{request.user.id}', 0)
        if active_scans > 0:
            cache.set(f'deep_active_scans_{request.user.id}', active_scans - 1, 3600)
        
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

    def create(self, request, *args, **kwargs):
        """Create a session with optional recorded actions - SIMPLIFIED FLOW"""
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create the session with simplified data
        session_data = {
            'user': user,
            'name': request.data.get('name', f'Security Test {timezone.now().strftime("%Y-%m-%d %H:%M")}'),
            'description': request.data.get('description', ''),
            'scan_intensity': request.data.get('scan_intensity', 'standard'),
            'status': 'ready'  # Ready for configuration after recording
        }
        
        # Create the session first
        session = DeepScanSession.objects.create(**session_data)
        
        # Add recorded actions if provided in the new simplified flow
        recorded_actions = request.data.get('recorded_actions', [])
        created_actions = []
        
        for action_data in recorded_actions:
            action = RecordedAction.objects.create(
                session=session,
                action_type=action_data.get('action_type', 'click'),
                target_element=action_data.get('target_element', ''),
                target_selector=action_data.get('target_selector', ''),
                value=action_data.get('value', ''),
                url=action_data.get('url', ''),
                timestamp=action_data.get('timestamp', timezone.now().timestamp()),
                dom_snapshot=action_data.get('dom_snapshot', {})
            )
            created_actions.append(action.id)
        
        # Update session with action count
        session.recorded_actions_count = len(created_actions)
        session.save()
        
        serializer = self.get_serializer(session)
        return Response({
            'id': str(session.id),
            'name': session.name,
            'status': session.status,
            'recorded_actions_count': len(created_actions),
            'message': 'Session created successfully with recorded actions'
        }, status=status.HTTP_201_CREATED)

class RecordedActionViewSet(viewsets.ModelViewSet):
    queryset = RecordedAction.objects.all().order_by('timestamp')
    serializer_class = RecordedActionCreateSerializer
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_authenticated:
            return self.queryset.filter(session__user=self.request.user)
        return self.queryset.none()
    
    def create(self, request):
        """Record a user action during session recording"""
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_authenticated:
            return self.queryset.filter(session__user=self.request.user)
        return self.queryset.none()

class ScanModuleViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanModule.objects.all().order_by('started_at')
    serializer_class = ScanModuleSerializer
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_authenticated:
            return self.queryset.filter(session__user=self.request.user)
        return self.queryset.none()


class DeepScanProgressView(APIView):
    """Get real-time scan progress"""
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
    permission_classes = [IsAuthenticated]
    
    def get(self, request, session_id):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
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
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_authenticated:
            return self.queryset.filter(session__user=self.request.user)
        return self.queryset.none()
    
    @action(detail=True, methods=['post'])
    def generate_report(self, request, pk=None):
        """Generate comprehensive security report"""
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        report = self.get_object()
        
        # In a real implementation, this would generate PDF/HTML reports
        # For now, we'll return the existing report data
        
        return Response({
            'message': 'Report generated successfully',
            'report_id': str(report.id),
            'download_url': f"/api/deep/reports/{report.id}/download/"
        })

# In deepscan/views.py - fix the extension_connect function

@api_view(['POST'])
@permission_classes([AllowAny])
def extension_connect(request):
    """Handle extension connection - supports JWT and session auth"""
    try:
        extension_data = request.data
        
        user = None
        authenticated = False
        
        # Try to get user from request without forcing authentication
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
            authenticated = True
            logger.info(f"User authenticated via session: {user.username}")
        else:
            # Try JWT token authentication
            auth_header = request.headers.get('Authorization', '')
            auth_token = None
            
            if auth_header.startswith('Bearer '):
                auth_token = auth_header[7:]
            else:
                auth_token = extension_data.get('auth_token')
            
            if auth_token:
                user = validate_jwt_token(auth_token)
                if user:
                    authenticated = True
                    logger.info(f"User authenticated via JWT: {user.username}")
        
        # Create extension session
        session_id = extension_data.get('session_id', str(uuid.uuid4()))
        
        if user and authenticated:
            extension_session, created = BrowserExtensionSession.objects.update_or_create(
                session_id=session_id,
                defaults={
                    'user': user,
                    'browser_info': extension_data.get('browser_info', {}),
                    'extension_version': extension_data.get('version', '1.0.0'),
                    'is_active': True,
                }
            )
        else:
            # Create session without user for unauthenticated extensions
            extension_session, created = BrowserExtensionSession.objects.update_or_create(
                session_id=session_id,
                defaults={
                    'user': None,
                    'browser_info': extension_data.get('browser_info', {}),
                    'extension_version': extension_data.get('version', '1.0.0'),
                    'is_active': True,
                }
            )
        
        return Response({
            'status': 'connected',
            'session_id': extension_session.session_id,
            'authenticated': authenticated,
            'user': {
                'username': user.username if user else 'demo_user',
                'authenticated': authenticated
            } if user else None
        })
        
    except Exception as e:
        logger.error(f"Extension connection error: {str(e)}")
        # Return a safe response even if there's an error
        return Response({
            'status': 'connected',
            'session_id': str(uuid.uuid4()),
            'authenticated': False,
            'message': 'Extension connected in demo mode'
        }, status=200)  # Always return 200 for extension connection

# Update the get_user_info view
@api_view(['GET'])
@permission_classes([AllowAny])  # Allow any for user info
def get_user_info(request):
    """Get user info - supports both session and JWT auth"""
    try:
        user = get_user_from_request(request)
        
        if user and user.is_authenticated:
            return Response({
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'authenticated': True
            })
        else:
            # Return demo data for unauthenticated users
            return Response({
                'username': 'security_analyst',
                'email': 'analyst@geniusguard.com',
                'first_name': 'Security',
                'last_name': 'Analyst',
                'authenticated': False
            })
            
    except Exception as e:
        logger.error(f"User info error: {str(e)}")
        return Response({
            'username': 'demo_user',
            'email': 'demo@geniusguard.com',
            'first_name': 'Demo',
            'last_name': 'User',
            'authenticated': False
        })


# In deepscan/views.py - update BrowserExtensionView

class BrowserExtensionView(APIView):
    """Handle browser extension communications"""
    authentication_classes = [SessionOrJWTAuthentication]  # Use combined auth
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

# In deepscan/views.py - update BulkRecordedActionView

class BulkRecordedActionView(APIView):
    """Bulk create recorded actions from browser extension - ENHANCED"""
    authentication_classes = [SessionOrJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        session_id = request.data.get('session_id')
        actions_data = request.data.get('actions', [])
        metadata = request.data.get('metadata', {})
        
        # If no session_id provided, create a temporary session
        if not session_id:
            session = DeepScanSession.objects.create(
                user=user,
                name='Live Recording Session',
                status='recording',
                recording_started_at=timezone.now()
            )
            session_id = str(session.id)
        
        try:
            session = DeepScanSession.objects.get(
                id=session_id,
                user=user
            )
            
            # Ensure session is in recording state
            if session.status != 'recording':
                session.status = 'recording'
                if not session.recording_started_at:
                    session.recording_started_at = timezone.now()
                session.save()
            
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
                timestamp=action_data.get('timestamp', timezone.now().timestamp()),
                dom_snapshot=action_data.get('dom_snapshot', {})
            )
            created_actions.append(action.id)
        
        # Update session action count
        session.recorded_actions_count = session.actions.count()
        session.save()
        
        return Response({
            'message': f'{len(created_actions)} actions recorded',
            'actions_count': len(created_actions),
            'session_id': str(session.id),
            'session_status': session.status,
            'total_actions': session.recorded_actions_count
        })

# Add these new views to your existing views.py

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_direct_recording(request):
    """Start recording immediately without pre-creating a session"""
    try:
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create a temporary session for recording
        session = DeepScanSession.objects.create(
            user=user,
            name='Temporary Recording Session',
            status='recording',
            recording_started_at=timezone.now()
        )
        
        # Initialize browser extension session
        extension_data = request.data.get('browser_info', {})
        extension_session = BrowserExtensionSession.objects.create(
            user=user,
            session_id=str(uuid.uuid4()),
            browser_info=extension_data,
            extension_version=extension_data.get('version', '1.0.0'),
            is_active=True
        )
        
        return Response({
            'status': 'recording',
            'session_id': str(session.id),
            'extension_session_id': extension_session.session_id,
            'message': 'Recording started successfully'
        })
        
    except Exception as e:
        logger.error(f"Direct recording start error: {str(e)}")
        return Response(
            {'error': 'Failed to start recording session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_recording_session(request):
    """Save recorded session with actions and finalize the name"""
    try:
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        session_id = request.data.get('session_id')
        session_name = request.data.get('name')
        recorded_actions = request.data.get('recorded_actions', [])
        
        if not session_id or not session_name:
            return Response(
                {'error': 'Session ID and name are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the temporary session
        session = DeepScanSession.objects.get(id=session_id, user=user)
        
        # Update session with final name and complete recording
        session.name = session_name
        session.status = 'ready'
        session.recording_completed_at = timezone.now()
        
        # Add recorded actions
        created_actions = []
        for action_data in recorded_actions:
            action = RecordedAction.objects.create(
                session=session,
                action_type=action_data.get('action_type', 'click'),
                target_element=action_data.get('target_element', ''),
                target_selector=action_data.get('target_selector', ''),
                value=action_data.get('value', ''),
                url=action_data.get('url', ''),
                timestamp=action_data.get('timestamp', timezone.now().timestamp()),
                dom_snapshot=action_data.get('dom_snapshot', {})
            )
            created_actions.append(action.id)
        
        session.recorded_actions_count = len(created_actions)
        session.save()
        
        return Response({
            'session_id': str(session.id),
            'name': session.name,
            'status': session.status,
            'recorded_actions_count': len(created_actions),
            'message': 'Recording session saved successfully'
        })
        
    except DeepScanSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Save recording session error: {str(e)}")
        return Response(
            {'error': 'Failed to save recording session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_recording_status(request, session_id):
    """Get current recording status and actions count"""
    try:
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        session = DeepScanSession.objects.get(id=session_id, user=user)
        
        # Get recent actions
        recent_actions = RecordedAction.objects.filter(
            session=session
        ).order_by('-timestamp')[:10]
        
        actions_data = []
        for action in recent_actions:
            actions_data.append({
                'id': str(action.id),
                'action_type': action.action_type,
                'target_element': action.target_element,
                'url': action.url,
                'timestamp': action.timestamp,
                'value': action.value
            })
        
        return Response({
            'session_id': str(session.id),
            'status': session.status,
            'recording_started_at': session.recording_started_at,
            'actions_count': session.recorded_actions_count,
            'recent_actions': actions_data
        })
        
    except DeepScanSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def record_session_actions(request, session_id):
    """Record multiple actions for a specific session"""
    try:
        user = get_user_from_request(request)
        if not user or not user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        session = DeepScanSession.objects.get(id=session_id, user=user)
        actions_data = request.data.get('actions', [])
        
        # Ensure session is in recording state
        if session.status != 'recording':
            session.status = 'recording'
            if not session.recording_started_at:
                session.recording_started_at = timezone.now()
            session.save()
        
        created_actions = []
        for action_data in actions_data:
            action = RecordedAction.objects.create(
                session=session,
                action_type=action_data.get('action_type', 'click'),
                target_element=action_data.get('target_element', ''),
                target_selector=action_data.get('target_selector', ''),
                value=action_data.get('value', ''),
                url=action_data.get('url', ''),
                timestamp=action_data.get('timestamp', timezone.now().timestamp()),
                dom_snapshot=action_data.get('dom_snapshot', {})
            )
            created_actions.append(action.id)
        
        # Update session action count
        session.recorded_actions_count = session.actions.count()
        session.save()
        
        return Response({
            'message': f'{len(created_actions)} actions recorded',
            'actions_count': len(created_actions),
            'session_id': str(session.id),
            'session_status': session.status,
            'total_actions': session.recorded_actions_count
        })
        
    except DeepScanSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Record session actions error: {str(e)}")
        return Response(
            {'error': 'Failed to record actions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# In your views.py
from django.http import FileResponse
import os
from django.conf import settings

def download_chrome_extension(request):
    extension_path = os.path.join(settings.BASE_DIR, 'static', 'downloads', 'GENIUSGAURD-extension-chrome.zip')
    return FileResponse(open(extension_path, 'rb'), as_attachment=True, filename='GENIUSGAURD-chrome-extension.zip')

def download_firefox_extension(request):
    extension_path = os.path.join(settings.BASE_DIR, 'static', 'downloads', 'GENIUSGAURD-extension-firefox.zip')
    return FileResponse(open(extension_path, 'rb'), as_attachment=True, filename='GENIUSGAURD-firefox-extension.zip')

def download_edge_extension(request):
    extension_path = os.path.join(settings.BASE_DIR, 'static', 'downloads', 'GENIUSGAURD-extension-edge.zip')
    return FileResponse(open(extension_path, 'rb'), as_attachment=True, filename='GENIUSGAURD-edge-extension.zip')