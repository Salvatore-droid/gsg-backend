from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.validators import URLValidator, MinValueValidator, MaxValueValidator
import uuid

User = get_user_model()

class ScanTarget(models.Model):
    SCAN_TYPES = (
        ('full', 'Full Scan'),
        ('quick', 'Quick Scan'),
        ('compliance', 'Compliance Scan'),
        ('continuous', 'Continuous Monitoring')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_targets', null=True)
    url = models.URLField(max_length=2048, validators=[URLValidator()])
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(blank=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, default='full')
    compliance_requirements = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scan_date = models.DateTimeField(null=True, blank=True)
    monitoring_interval = models.IntegerField(
        default=24,  # hours
        validators=[MinValueValidator(1), MaxValueValidator(168)]  # 1 hour to 1 week
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['url']),
        ]

    def __str__(self):
        return f"{self.name} ({self.url})"

class ScanResult(models.Model):
    STATUS_CHOICES = (
        ('queued', 'Queued'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scan_results')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    scan_duration = models.FloatField(null=True, blank=True)  # in seconds
    progress = models.IntegerField(default=0)
    current_activity = models.CharField(max_length=255, blank=True)
    risk_score = models.FloatField(
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    total_vulnerabilities = models.IntegerField(default=0)
    raw_data = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['target', 'status']),
            models.Index(fields=['started_at']),
        ]

    def __str__(self):
        return f"Scan {self.id} - {self.target.name}"

    def update_progress(self, progress, activity):
        self.progress = progress
        self.current_activity = activity
        self.save(update_fields=['progress', 'current_activity'])

class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0), MaxValueValidator(10)]
    )
    cve_ids = models.JSONField(default=list)
    evidence = models.TextField()
    recommendation = models.TextField()
    is_false_positive = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='verified_vulnerabilities'
    )
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-cvss_score']
        indexes = [
            models.Index(fields=['scan_result', 'severity']),
            models.Index(fields=['cvss_score']),
        ]

    def __str__(self):
        return f"{self.title} ({self.severity})"

class ThreatIntelligence(models.Model):
    SEVERITY_CHOICES = (
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    threat_id = models.CharField(max_length=255, unique=True, null=True)
    title = models.CharField(max_length=255, null=True)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    indicators = models.JSONField(default=list)
    detected_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    source = models.CharField(max_length=255, null=True)
    confidence_score = models.FloatField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=True
    )

    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['threat_id']),
            models.Index(fields=['severity', 'is_active']),
        ]

    def __str__(self):
        return f"{self.title} ({self.threat_id})"

class GlobalStats(models.Model):
    total_scans = models.IntegerField(default=0)
    total_vulnerabilities_found = models.IntegerField(default=0)
    high_risk_scans = models.IntegerField(default=0)
    average_scan_duration = models.FloatField(default=0.0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Global Stats (Updated: {self.last_updated})"

class ScanConfiguration(models.Model):
    target = models.OneToOneField(
        ScanTarget,
        on_delete=models.CASCADE,
        related_name='configuration'
    )
    max_depth = models.IntegerField(default=3)
    timeout = models.IntegerField(default=300)  # seconds
    user_agent = models.CharField(max_length=255, blank=True)
    excluded_paths = models.JSONField(default=list)
    authentication_required = models.BooleanField(default=False)
    auth_credentials = models.JSONField(default=dict)
    custom_headers = models.JSONField(default=dict)
    scan_schedule = models.JSONField(default=dict)
    notifications_enabled = models.BooleanField(default=True)
    notification_channels = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Configuration for {self.target.name}"
