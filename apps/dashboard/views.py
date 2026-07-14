from django.views.generic import TemplateView
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from apps.scanner.models import ScanJob
from apps.domains.models import Domain
from apps.accounts.models import Organization
from apps.scoring.models import TrustScore
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta


class LandingPageView(TemplateView):
    template_name = 'landing.html'


@method_decorator(staff_member_required, name='dispatch')
class AdminDashboardView(TemplateView):
    template_name = 'admin_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Stats
        total_organizations = Organization.objects.filter(is_deleted=False).count()
        total_domains = Domain.objects.filter(is_deleted=False).count()
        total_scans = ScanJob.objects.count()
        completed_scans = ScanJob.objects.filter(status='completed').count()
        
        # Recent scans
        recent_scans = ScanJob.objects.select_related('domain', 'domain__organization').order_by('-created_at')[:10]
        
        # Average trust score
        avg_score = TrustScore.objects.filter(is_deleted=False).aggregate(avg=Avg('overall'))['avg'] or 0
        
        # Scans this week
        week_ago = timezone.now() - timedelta(days=7)
        scans_this_week = ScanJob.objects.filter(created_at__gte=week_ago).count()
        
        context = {
            'total_organizations': total_organizations,
            'total_domains': total_domains,
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'avg_score': round(avg_score, 1),
            'scans_this_week': scans_this_week,
            'recent_scans': recent_scans,
            'success_rate': round((completed_scans / total_scans * 100) if total_scans > 0 else 0, 1),
        }
        return context


admin_dashboard = AdminDashboardView.as_view()