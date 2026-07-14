import uuid
import hashlib
import hmac
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from apps.accounts.models import User, Organization, Membership
from apps.domains.models import Domain
from apps.scanner.models import ScanJob
from apps.scoring.models import TrustScore
from apps.reconnaissance.models import Finding


class LandingPageView(TemplateView):
    template_name = 'landing.html'


class ScanPageView(TemplateView):
    template_name = 'scan/index.html'

    def post(self, request):
        domain_name = request.POST.get('domain', '').strip().lower()
        domain_name = domain_name.replace('http://', '').replace('https://', '').replace('www.', '').strip('/')

        if not domain_name:
            return render(request, 'scan/index.html', {'error': 'Please enter a domain name'})

        domain, created = Domain.objects.get_or_create(
            name=domain_name,
            defaults={
                'organization': None,
                'root_domain': Domain.extract_root_domain(domain_name),
                'tld': Domain.extract_tld(domain_name),
                'tld_category': Domain.determine_tld_category(Domain.extract_tld(domain_name)),
            }
        )

        scan_job = ScanJob.objects.create(
            domain=domain,
            status='pending',
            scan_type='domain_full',
            trigger_source='web',
            authorization_verified=False,
        )

        from apps.scanner.tasks import orchestrate_scan
        orchestrate_scan.delay(str(scan_job.id))

        return redirect('scan_results', scan_id=scan_job.id)


class ScanResultsView(TemplateView):
    template_name = 'scan/results.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scan_job = get_object_or_404(ScanJob, id=kwargs['scan_id'])
        context['scan_job'] = scan_job
        context['domain'] = scan_job.domain
        score = TrustScore.objects.filter(scan_job=scan_job).first()
        context['trust_score'] = score.overall if score else None
        context['risk_level'] = score.risk_level if score else 'Unknown'
        findings = Finding.objects.filter(scan_job=scan_job, is_deleted=False, is_false_positive=False)
        context['findings'] = findings[:50]
        context['findings_count'] = findings.count()
        if scan_job.completed_at and scan_job.created_at:
            delta = scan_job.completed_at - scan_job.created_at
            context['duration'] = f'{delta.seconds//60}m {delta.seconds%60}s'
        else:
            context['duration'] = 'In progress'
        context['dimensions'] = [
            {'name': 'Email Security', 'score': score.email_security if score else 0, 'description': 'SPF, DKIM, DMARC posture'},
            {'name': 'Infrastructure', 'score': score.infrastructure_hygiene if score else 0, 'description': 'SSL, DNS, hosting security'},
            {'name': 'Exposure Surface', 'score': score.exposure_surface if score else 0, 'description': 'Public-facing risk surface'},
            {'name': 'Breach History', 'score': score.breach_history if score else 0, 'description': 'Known breaches & leaks'},
            {'name': 'Reputation', 'score': score.reputation_trust if score else 0, 'description': 'Blacklists & trust signals'},
            {'name': 'Identity', 'score': score.identity_integrity if score else 0, 'description': 'Domain ownership & verification'},
        ]
        critical = findings.filter(severity='critical')[:3]
        high = findings.filter(severity='high')[:3]
        medium = findings.filter(severity='medium')[:3]
        context['top_risks'] = list(critical) + list(high) + list(medium)
        return context


class RegisterView(View):
    def get(self, request):
        return render(request, 'registration/register.html')

    def post(self, request):
        email = request.POST.get('email', '').strip().lower()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        name = request.POST.get('name', '').strip()

        if not email or not password1:
            return render(request, 'registration/register.html', {'error': 'Email and password are required'})
        if password1 != password2:
            return render(request, 'registration/register.html', {'error': 'Passwords do not match'})
        if len(password1) < 8:
            return render(request, 'registration/register.html', {'error': 'Password must be at least 8 characters'})
        if User.objects.filter(email=email).exists():
            return render(request, 'registration/register.html', {'error': 'Email already registered'})

        username = email.split('@')[0]
        base_username = username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1,
        )
        user.first_name = name
        user.save(update_fields=['first_name'])

        org = Organization.objects.create(
            name=f"{name or email}'s Organization",
            slug=f"org-{uuid.uuid4().hex[:8]}",
        )

        Membership.objects.create(
            user=user,
            organization=org,
            role='owner',
        )

        login(request, user)
        messages.success(request, 'Account created successfully!')
        return redirect('dashboard')


class LoginView(View):
    def get(self, request):
        return render(request, 'registration/login.html')

    def post(self, request):
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        return render(request, 'registration/login.html', {'form': AuthenticationForm(), 'error': 'Invalid email or password'})


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            orgs = list(self.request.user.memberships.values_list('organization_id', flat=True))
        except Exception:
            orgs = []
        context['domain_count'] = Domain.objects.filter(organization_id__in=orgs, is_deleted=False).count()
        context['authorized_domain_count'] = Domain.objects.filter(organization_id__in=orgs, authorization_status='authorized').count()
        context['scan_count'] = ScanJob.objects.filter(domain__organization_id__in=orgs).count()
        context['completed_scan_count'] = ScanJob.objects.filter(domain__organization_id__in=orgs, status='completed').count()
        context['recent_domains'] = Domain.objects.filter(organization_id__in=orgs).order_by('-created_at')[:10]
        context['recent_scans'] = ScanJob.objects.filter(domain__organization_id__in=orgs).select_related('domain').order_by('-created_at')[:10]

        latest_scores = TrustScore.objects.filter(domain__organization_id__in=orgs).order_by('-calculated_at')
        if latest_scores.exists():
            from django.db.models import Avg
            avg = TrustScore.objects.filter(domain__organization_id__in=orgs).aggregate(Avg('overall'))
            context['avg_score'] = round(avg['overall__avg'] or 0, 1)
        else:
            context['avg_score'] = 0

        finding_ids = Finding.objects.filter(scan_job__domain__organization_id__in=orgs).values_list('id', flat=True)
        context['finding_count'] = len(finding_ids)
        context['critical_findings'] = Finding.objects.filter(id__in=finding_ids, severity='critical').count()
        return context


@csrf_exempt
def send_magic_link(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)

        token = uuid.uuid4().hex
        expires_at = timezone.now() + timezone.timedelta(minutes=15)
        request.session['magic_link_token'] = token
        request.session['magic_link_email'] = email
        request.session['magic_link_expires'] = expires_at.isoformat()

        magic_link = f"{request.scheme}://{request.get_host()}/auth/magic-link/verify/?token={token}&email={email}"

        html = render_to_string('emails/magic_link.html', {'magic_link_url': magic_link})

        msg = EmailMultiAlternatives(
            subject='Sign in to TrustScan',
            body=f'Click this link to sign in: {magic_link}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        msg.attach_alternative(html, 'text/html')
        try:
            msg.send()
        except Exception:
            pass

        return JsonResponse({'status': 'sent', 'email': email})
    return JsonResponse({'error': 'POST required'}, status=405)


def verify_magic_link(request):
    token = request.GET.get('token', '')
    email = request.GET.get('email', '').strip().lower()
    stored_token = request.session.get('magic_link_token', '')
    stored_email = request.session.get('magic_link_email', '')
    expires_at = request.session.get('magic_link_expires', '')

    if token == stored_token and email == stored_email:
        try:
            expires = timezone.datetime.fromisoformat(expires_at)
            if timezone.now() > expires:
                return render(request, 'registration/login.html', {'error': 'Magic link has expired. Request a new one.'})
        except Exception:
            pass

        user = User.objects.filter(email=email).first()
        if not user:
            username = email.split('@')[0]
            base_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            user = User.objects.create_user(username=username, email=email, password=uuid.uuid4().hex)
            org = Organization.objects.create(name=f"{email}'s Organization", slug=f"org-{uuid.uuid4().hex[:8]}")
            Membership.objects.create(user=user, organization=org, role='owner')

        login(request, user)
        request.session.pop('magic_link_token', None)
        request.session.pop('magic_link_email', None)
        request.session.pop('magic_link_expires', None)
        return redirect('dashboard')

    return render(request, 'registration/login.html', {'error': 'Invalid magic link'})


@csrf_exempt
def init_view(request):
    from django.core.management import call_command
    import io, sys

    out = io.StringIO()
    err = io.StringIO()

    # Run migrations
    out.write('Running migrations...\n')
    try:
        call_command('migrate', '--noinput', stdout=out, stderr=err)
        out.write('Migrations done.\n')
    except Exception as e:
        out.write(f'Migrate error: {e}\n')

    # Create superuser
    out.write('Creating superuser...\n')
    try:
        User = __import__('apps.accounts.models', fromlist=['User']).User
        user, created = User.objects.get_or_create(
            email='joelkaunda15@gmail.com',
            defaults={
                'username': 'joelkaunda',
                'first_name': 'Joel',
                'last_name': 'Kaunda',
                'is_staff': True,
                'is_superuser': True,
            }
        )
        if created:
            user.set_password('Incorrect9.')
            user.save()
            out.write('Superuser created!\n')
        else:
            out.write('Superuser already exists\n')
    except Exception as e:
        out.write(f'User error: {e}\n')

    # Create Organization + Membership if missing
    out.write('Creating organization...\n')
    try:
        Organization = __import__('apps.accounts.models', fromlist=['Organization']).Organization
        org, org_created = Organization.objects.get_or_create(
            name="Joel Kaunda's Organization",
            defaults={'slug': f'org-{uuid.uuid4().hex[:8]}'}
        )
        if org_created:
            out.write('Organization created!\n')
        Membership = __import__('apps.accounts.models', fromlist=['Membership']).Membership
        Membership.objects.get_or_create(
            user=user,
            organization=org,
            defaults={'role': 'owner'}
        )
        out.write('Membership ensured.\n')
    except Exception as e:
        out.write(f'Org error: {e}\n')

    content = out.getvalue() + err.getvalue()
    return JsonResponse({'status': 'ok', 'log': content})
