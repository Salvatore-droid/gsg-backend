from rest_framework import serializers
from django.utils import timezone
from .models import (
    ScanTarget, 
    ScanResult, 
    Vulnerability, 
    ThreatIntelligence, 
    GlobalStats,
    ScanConfiguration
)

class ScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanConfiguration
        fields = [
            'id', 'max_depth', 'timeout', 'user_agent', 'excluded_paths',
            'authentication_required', 'auth_credentials', 'custom_headers',
            'scan_schedule', 'notifications_enabled', 'notification_channels'
        ]
        extra_kwargs = {
            'auth_credentials': {'write_only': True}
        }

class ScanTargetSerializer(serializers.ModelSerializer):
    configuration = ScanConfigurationSerializer(required=False)
    last_scan_status = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanTarget
        fields = [
            'id', 'url', 'name', 'description', 'scan_type',
            'compliance_requirements', 'is_active', 'created_at',
            'updated_at', 'last_scan_date', 'monitoring_interval',
            'configuration', 'last_scan_status'
        ]
        read_only_fields = ['created_at', 'updated_at', 'last_scan_date']

    def get_last_scan_status(self, obj):
        last_scan = obj.scan_results.first()
        if last_scan:
            return {
                'status': last_scan.status,
                'risk_score': last_scan.risk_score,
                'total_vulnerabilities': last_scan.total_vulnerabilities
            }
        return None

    def create(self, validated_data):
        configuration_data = validated_data.pop('configuration', None)
        scan_target = ScanTarget.objects.create(**validated_data)
        
        if configuration_data:
            ScanConfiguration.objects.create(target=scan_target, **configuration_data)
        else:
            ScanConfiguration.objects.create(target=scan_target)
            
        return scan_target

class VulnerabilitySerializer(serializers.ModelSerializer):
    scan_result_id = serializers.UUIDField(source='scan_result.id', read_only=True)
    target_url = serializers.CharField(source='scan_result.target.url', read_only=True)
    
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'scan_result_id', 'target_url', 'title', 'description', 
            'severity', 'cvss_score', 'cve_ids', 'evidence', 'recommendation', 
            'is_false_positive', 'is_verified', 'verified_by', 'created_at', 
            'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

class ScanResultSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    target_url = serializers.SerializerMethodField()
    target_name = serializers.CharField(source='target.name', read_only=True)
    duration_formatted = serializers.SerializerMethodField()
    scan_type = serializers.CharField(source='target.scan_type', read_only=True)

    class Meta:
        model = ScanResult
        fields = [
            'id', 'target', 'target_url', 'target_name', 'scan_type',
            'status', 'started_at', 'completed_at', 'scan_duration', 
            'duration_formatted', 'progress', 'current_activity', 
            'risk_score', 'total_vulnerabilities', 'raw_data', 
            'error_message', 'vulnerabilities'
        ]
        read_only_fields = [
            'id', 'started_at', 'completed_at', 'scan_duration',
            'progress', 'risk_score', 'total_vulnerabilities'
        ]

    def get_target_url(self, obj):
        return obj.target.url

    def get_duration_formatted(self, obj):
        if obj.scan_duration:
            minutes = int(obj.scan_duration // 60)
            seconds = int(obj.scan_duration % 60)
            return f"{minutes}m {seconds}s"
        return None

class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    age = serializers.SerializerMethodField()
    time_ago = serializers.SerializerMethodField()

    class Meta:
        model = ThreatIntelligence
        fields = [
            'id', 'threat_id', 'title', 'description', 'severity',
            'indicators', 'detected_at', 'is_active', 'created_at',
            'updated_at', 'source', 'confidence_score', 'age', 'time_ago'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_age(self, obj):
        if obj.detected_at:
            time_diff = timezone.now() - obj.detected_at
            days = time_diff.days
            hours = time_diff.seconds // 3600
            if days > 0:
                return f"{days} days"
            return f"{hours} hours"
        return None

    def get_time_ago(self, obj):
        """More detailed time ago format for frontend display"""
        if obj.detected_at:
            time_diff = timezone.now() - obj.detected_at
            
            days = time_diff.days
            hours = time_diff.seconds // 3600
            minutes = (time_diff.seconds % 3600) // 60
            
            if days > 0:
                return f"{days}d ago" if days == 1 else f"{days}d ago"
            elif hours > 0:
                return f"{hours}h ago" if hours == 1 else f"{hours}h ago"
            else:
                return f"{minutes}m ago" if minutes > 0 else "Just now"
        return "Unknown"

class GlobalStatsSerializer(serializers.ModelSerializer):
    success_rate = serializers.SerializerMethodField()
    average_risk_score = serializers.SerializerMethodField()
    threats_blocked = serializers.SerializerMethodField()

    class Meta:
        model = GlobalStats
        fields = [
            'id', 'total_scans', 'total_vulnerabilities_found',
            'high_risk_scans', 'average_scan_duration',
            'last_updated', 'success_rate', 'average_risk_score',
            'threats_blocked'
        ]
        read_only_fields = fields

    def get_success_rate(self, obj):
        """Calculate success rate based on scans vs high risk scans"""
        if obj.total_scans > 0:
            success_rate = ((obj.total_scans - obj.high_risk_scans) / obj.total_scans) * 100
            return round(success_rate, 1)
        return 100.0

    def get_average_risk_score(self, obj):
        """Calculate average risk score (placeholder - you might want to compute this from actual scan data)"""
        return 42.5  # Placeholder - implement based on your data

    def get_threats_blocked(self, obj):
        """Calculate threats blocked based on vulnerabilities found"""
        return obj.total_vulnerabilities_found

class QuickScanRequestSerializer(serializers.Serializer):
    url = serializers.URLField(max_length=2048)
    scan_type = serializers.ChoiceField(
        choices=['quick', 'basic'],
        default='quick'
    )

    def validate_url(self, value):
        # Add custom URL validation if needed
        return value

class QuickScanResponseSerializer(serializers.Serializer):
    """Serializer for quick scan response"""
    url = serializers.URLField()
    scan_time = serializers.DateTimeField()
    findings = serializers.DictField()
    risk_score = serializers.FloatField(min_value=0, max_value=100)
    total_vulnerabilities = serializers.IntegerField(min_value=0)
    scan_duration = serializers.FloatField(min_value=0)

class ScanSummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    target_name = serializers.CharField(source='target.name')
    target_url = serializers.CharField(source='target.url')
    scan_type = serializers.CharField(source='target.scan_type')

    class Meta:
        model = ScanResult
        fields = [
            'id', 'target_name', 'target_url', 'scan_type', 'status',
            'started_at', 'risk_score', 'total_vulnerabilities'
        ]

class VulnerabilityStatisticsSerializer(serializers.Serializer):
    severity = serializers.CharField()
    count = serializers.IntegerField()
    percentage = serializers.FloatField()

class ScanResultsFilterSerializer(serializers.Serializer):
    start_date = serializers.DateTimeField(required=False)
    end_date = serializers.DateTimeField(required=False)
    status = serializers.ChoiceField(
        choices=ScanResult.STATUS_CHOICES,
        required=False
    )
    min_risk_score = serializers.FloatField(required=False)
    target_id = serializers.UUIDField(required=False)

# NEW SERIALIZERS ADDED BELOW

class LiveThreatFeedSerializer(serializers.Serializer):
    """Serializer for live threat feed endpoint"""
    id = serializers.IntegerField()
    type = serializers.CharField()
    title = serializers.CharField()
    detected_at = serializers.DateTimeField()
    severity = serializers.CharField()
    time_ago = serializers.SerializerMethodField()

    def get_time_ago(self, obj):
        """Format time ago for frontend display"""
        if 'detected_at' in obj:
            detected_at = obj['detected_at']
            if isinstance(detected_at, str):
                from django.utils.dateparse import parse_datetime
                detected_at = parse_datetime(detected_at)
            
            if detected_at:
                time_diff = timezone.now() - detected_at
                seconds = time_diff.total_seconds()
                
                if seconds < 60:
                    return f"{int(seconds)}s ago"
                elif seconds < 3600:
                    minutes = int(seconds // 60)
                    return f"{minutes}m ago"
                else:
                    hours = int(seconds // 3600)
                    return f"{hours}h ago"
        return "Unknown"

class ScanStatusSerializer(serializers.ModelSerializer):
    """Serializer for scan status endpoint"""
    target_url = serializers.CharField(source='target.url', read_only=True)
    target_name = serializers.CharField(source='target.name', read_only=True)
    duration_formatted = serializers.SerializerMethodField()

    class Meta:
        model = ScanResult
        fields = [
            'id', 'target_url', 'target_name', 'status', 'progress',
            'current_activity', 'started_at', 'scan_duration',
            'duration_formatted', 'risk_score', 'total_vulnerabilities',
            'error_message'
        ]
        read_only_fields = fields

    def get_duration_formatted(self, obj):
        if obj.scan_duration:
            minutes = int(obj.scan_duration // 60)
            seconds = int(obj.scan_duration % 60)
            return f"{minutes}m {seconds}s"
        return "In progress"

class VulnerabilityListSerializer(serializers.ModelSerializer):
    """Serializer for vulnerability list endpoint"""
    scan_target = serializers.CharField(source='scan_result.target.url', read_only=True)
    scan_date = serializers.DateTimeField(source='scan_result.started_at', read_only=True)
    risk_score = serializers.FloatField(source='scan_result.risk_score', read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'title', 'description', 'severity', 'cvss_score',
            'scan_target', 'scan_date', 'risk_score', 'evidence',
            'recommendation', 'is_false_positive', 'created_at'
        ]
        read_only_fields = fields

class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics"""
    total_scans = serializers.IntegerField()
    high_risk_scans = serializers.IntegerField()
    total_vulnerabilities_found = serializers.IntegerField()
    average_scan_duration = serializers.FloatField()
    success_rate = serializers.FloatField()
    recent_threats_count = serializers.IntegerField()
    active_scans = serializers.IntegerField()

class ThreatIntelFeedSerializer(serializers.ModelSerializer):
    """Serializer for threat intelligence feed with frontend-friendly format"""
    time_display = serializers.SerializerMethodField()
    icon = serializers.SerializerMethodField()

    class Meta:
        model = ThreatIntelligence
        fields = [
            'id', 'title', 'description', 'severity', 'detected_at',
            'source', 'confidence_score', 'time_display', 'icon'
        ]

    def get_time_display(self, obj):
        """Format time for frontend display"""
        if obj.detected_at:
            time_diff = timezone.now() - obj.detected_at
            seconds = time_diff.total_seconds()
            
            if seconds < 60:
                return f"{int(seconds)}s ago"
            elif seconds < 3600:
                minutes = int(seconds // 60)
                return f"{minutes}m ago"
            elif seconds < 86400:
                hours = int(seconds // 3600)
                return f"{hours}h ago"
            else:
                days = int(seconds // 86400)
                return f"{days}d ago"
        return "Unknown"

    def get_icon(self, obj):
        """Get appropriate icon based on threat type"""
        title_lower = obj.title.lower()
        if 'xss' in title_lower:
            return '⚡'
        elif 'sql' in title_lower or 'injection' in title_lower:
            return '💉'
        elif 'rce' in title_lower or 'remote code' in title_lower:
            return '🎯'
        elif 'csrf' in title_lower:
            return '🔄'
        elif 'lfi' in title_lower or 'file inclusion' in title_lower:
            return '📁'
        else:
            return '⚠️'

# Utility serializers for API responses
class APIResponseSerializer(serializers.Serializer):
    """Generic API response serializer"""
    success = serializers.BooleanField()
    message = serializers.CharField(required=False)
    data = serializers.DictField(required=False)
    errors = serializers.ListField(required=False)

class ErrorResponseSerializer(serializers.Serializer):
    """Error response serializer"""
    error = serializers.CharField()
    code = serializers.CharField(required=False)
    details = serializers.DictField(required=False)