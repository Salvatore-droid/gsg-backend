from rest_framework import serializers
from .models import (
    DeepScanSession, ScanModule, DeepScanFinding, 
    BrowserExtensionSession, RecordedAction, DeepScanReport
)
from base.models import ScanTarget

class RecordedActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecordedAction
        fields = '__all__'
        read_only_fields = ('id', 'session')

class BrowserExtensionSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BrowserExtensionSession
        fields = '__all__'
        read_only_fields = ('id', 'user', 'created_at', 'last_activity')

class DeepScanSessionSerializer(serializers.ModelSerializer):
    recorded_actions = RecordedActionSerializer(many=True, read_only=True)
    target_url = serializers.CharField(source='target.url', read_only=True, allow_null=True)
    target_name = serializers.CharField(source='target.name', read_only=True, allow_null=True)
    
    class Meta:
        model = DeepScanSession
        fields = '__all__'
        read_only_fields = (
            'id', 'user', 'created_at', 'recording_started_at', 
            'recording_completed_at', 'scan_started_at', 'scan_completed_at',
            'progress', 'status', 'total_vulnerabilities', 'risk_score'
        )
        extra_kwargs = {
            'target': {'required': False, 'allow_null': True}
        }
    
    def create(self, validated_data):
        # Handle target separately - it's optional
        target = validated_data.pop('target', None)
        instance = DeepScanSession.objects.create(**validated_data)
        if target:
            instance.target = target
            instance.save()
        return instance

class ScanModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanModule
        fields = '__all__'
        read_only_fields = ('id', 'session', 'started_at', 'completed_at')

class DeepScanFindingSerializer(serializers.ModelSerializer):
    module_name = serializers.CharField(source='module.name', read_only=True)
    
    class Meta:
        model = DeepScanFinding
        fields = '__all__'
        read_only_fields = ('id', 'session', 'module', 'detected_at')

class DeepScanReportSerializer(serializers.ModelSerializer):
    session_name = serializers.CharField(source='session.name', read_only=True)
    target_url = serializers.CharField(source='session.target.url', read_only=True, allow_null=True)
    
    class Meta:
        model = DeepScanReport
        fields = '__all__'
        read_only_fields = ('id', 'session', 'generated_at')

# Request/Response serializers
class SessionRecordingStartSerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    browser_info = serializers.JSONField(required=False)

class RecordedActionCreateSerializer(serializers.Serializer):
    action_type = serializers.ChoiceField(choices=RecordedAction.ACTION_TYPES)
    target_element = serializers.CharField(max_length=1000)
    target_selector = serializers.CharField(max_length=1000, required=False, allow_blank=True)
    value = serializers.CharField(required=False, allow_blank=True)
    url = serializers.URLField()
    timestamp = serializers.FloatField()
    screenshot_data = serializers.CharField(required=False, allow_blank=True)
    dom_snapshot = serializers.JSONField(required=False)

class ScanConfigurationSerializer(serializers.Serializer):
    scan_intensity = serializers.ChoiceField(choices=[
        ('quick', 'Quick Scan'),
        ('standard', 'Standard Audit'),
        ('comprehensive', 'Deep Audit')
    ])
    vulnerability_focus = serializers.ListField(
        child=serializers.CharField(max_length=50)
    )
    advanced_options = serializers.JSONField()

class DeepScanProgressSerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    progress = serializers.FloatField(min_value=0, max_value=100)
    current_module = serializers.CharField(required=False)
    status = serializers.CharField()

# ADD THIS NEW SERIALIZER FOR CREATING SESSIONS WITHOUT TARGET
class DeepScanSessionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeepScanSession
        fields = ['name', 'description', 'scan_intensity', 'target']
        extra_kwargs = {
            'target': {'required': False, 'allow_null': True},
            'name': {'required': True},
            'description': {'required': False, 'allow_blank': True},
            'scan_intensity': {'required': False, 'default': 'standard'}
        }