import requests

# Test without cookies (fresh user)
session = requests.Session()
for url in [
    'https://trustscan.snapdeploy.dev/',
    'https://trustscan.snapdeploy.dev/login/',
    'https://trustscan.snapdeploy.dev/login',
    'https://trustscan.snapdeploy.dev/register/',
    'https://trustscan.snapdeploy.dev/register',
    'https://trustscan.snapdeploy.dev/scan/',
    'https://trustscan.snapdeploy.dev/scan',
    'https://trustscan.snapdeploy.dev/about/',
    'https://trustscan.snapdeploy.dev/health/',
    'https://trustscan.snapdeploy.dev/health',
]:
    try:
        r = session.get(url, timeout=10, allow_redirects=False)
        desc = ''
        if r.status_code == 200:
            if 'Sign In' in r.text: desc = ' (login page)'
            elif 'Scan' in r.text and 'Domain' in r.text: desc = ' (scan page)'
            elif 'Create Account' in r.text or 'create your account' in r.text.lower(): desc = ' (register page)'
            elif 'TrustScan' in r.text and 'Digital' in r.text: desc = ' (landing page)'
            elif 'healthy' in r.text: desc = ' (health check)'
            elif 'About' in r.text: desc = ' (about page)'
            elif 'Privacy' in r.text: desc = ' (privacy page)'
        loc = ''
        if r.status_code in (301, 302, 307, 308):
            loc = f' -> {r.headers.get("Location", "")}'
        print(f'{url} -> {r.status_code}{desc}{loc}')
    except Exception as e:
        print(f'{url} -> {type(e).__name__}: {e}')
