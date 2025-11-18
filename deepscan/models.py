from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
from base.models import ScanTarget

User = get_user_model()

class DeepScanSession(models.Model):
    STATUS_CHOICES = (
        ('configuring', 'Configuring'),
        ('recording', 'Recording Session'),
        ('ready', 'Ready to Scan'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('paused', 'Paused'),
        ('cancelled', 'Cancelled')
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name='deep_scan_sessions')
    target = models.ForeignKey(ScanTarget, on_delete=models.SET_NULL, blank=True, null=True, related_name='deep_scans')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Configuration
    scan_intensity = models.CharField(
        max_length=20, 
        choices=(
            ('quick', 'Quick Scan'),
            ('standard', 'Standard Audit'), 
            ('comprehensive', 'Deep Audit')
        ),
        default='standard'
    )
    
    # Session recording data
    recorded_actions = models.JSONField(default=list)
    session_data = models.JSONField(default=dict)  # Cookies, localStorage, etc.
    
    # Scan configuration
    vulnerability_focus = models.JSONField(default=list)  # Selected vulnerability types
    advanced_options = models.JSONField(default=dict)
    
    # Scan progress
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='configuring')
    progress = models.FloatField(default=0.0)  # 0-100
    current_module = models.CharField(max_length=100, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    recording_started_at = models.DateTimeField(null=True, blank=True)
    recording_completed_at = models.DateTimeField(null=True, blank=True)
    scan_started_at = models.DateTimeField(null=True, blank=True)
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    
    # Results
    total_vulnerabilities = models.IntegerField(default=0)
    risk_score = models.FloatField(null=True, blank=True)
    scan_duration = models.FloatField(null=True, blank=True)  # in seconds
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"DeepScan: {self.name} - {self.target.url}"

class ScanModule(models.Model):
    session = models.ForeignKey(DeepScanSession, on_delete=models.CASCADE, related_name='modules')
    name = models.CharField(max_length=100)
    module_type = models.CharField(max_length=50)
    status = models.CharField(
        max_length=20,
        choices=(
            ('pending', 'Pending'),
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ),
        default='pending'
    )
    progress = models.FloatField(default=0.0)
    findings_count = models.IntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['started_at']

class DeepScanFinding(models.Model):
    SEVERITY_CHOICES = (
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational')
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(DeepScanSession, on_delete=models.CASCADE, related_name='findings')
    module = models.ForeignKey(ScanModule, on_delete=models.CASCADE, related_name='module_findings', null=True)
    
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(default=0.0)
    
    # Location and context
    url = models.URLField(max_length=2000, blank=True)
    http_method = models.CharField(max_length=10, blank=True)
    parameter = models.CharField(max_length=500, blank=True)
    payload = models.TextField(blank=True)
    
    # Evidence and reproduction
    request_data = models.JSONField(default=dict)
    response_data = models.JSONField(default=dict)
    evidence = models.TextField(blank=True)
    
    # Mitigation
    recommendation = models.TextField()
    remediation_complexity = models.CharField(
        max_length=20,
        choices=(
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High')
        ),
        default='medium'
    )
    
    # Metadata
    detected_at = models.DateTimeField(default=timezone.now)
    is_false_positive = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-cvss_score', '-detected_at']
    
    def __str__(self):
        return f"{self.title} ({self.severity})"

# In deepscan/models.py - update BrowserExtensionSession
class BrowserExtensionSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='extension_sessions', null=True, blank=True)  # ADD null=True, blank=True
    session_id = models.CharField(max_length=100, unique=True)
    browser_info = models.JSONField(default=dict)
    extension_version = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)

class RecordedAction(models.Model):
    ACTION_TYPES = (
        ('navigation', 'Navigation'),
        ('click', 'Click'),
        ('input', 'Input'),
        ('submit', 'Submit'),
        ('scroll', 'Scroll'),
        ('hover', 'Hover'),
        ('keypress', 'Key Press')
    )
    
    session = models.ForeignKey(DeepScanSession, on_delete=models.CASCADE, related_name='actions')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    target_element = models.CharField(max_length=1000)
    target_selector = models.CharField(max_length=1000, blank=True)
    value = models.TextField(blank=True)
    url = models.URLField(max_length=2000)
    timestamp = models.FloatField()  # Relative time in seconds
    screenshot_data = models.TextField(blank=True)  # Base64 encoded screenshot
    dom_snapshot = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['timestamp']

class DeepScanReport(models.Model):
    session = models.OneToOneField(DeepScanSession, on_delete=models.CASCADE, related_name='report')
    executive_summary = models.TextField()
    technical_summary = models.JSONField(default=dict)
    risk_metrics = models.JSONField(default=dict)
    recommendations = models.JSONField(default=list)
    generated_at = models.DateTimeField(auto_now_add=True)
    report_data = models.JSONField(default=dict)  # Full report data
    
    def __str__(self):
        return f"Report for {self.session.name}"