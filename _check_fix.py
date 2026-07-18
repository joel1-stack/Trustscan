import requests

base = 'https://trustscan.snapdeploy.dev'
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# Test if SnapDeploy intercepted /auth/login
for path in ['/auth/login', '/auth/register', '/auth/login/', '/auth/register/']:
    r = requests.get(base + path, headers=headers, timeout=15, allow_redirects=False)
    is_snap = 'SnapDeploy' in r.text[:500] or 'snapdeploy' in r.text[:500].lower()
    loc = r.headers.get('location', '')
    print(f'{path}: {r.status_code} {"[SNAPDEPLOY]" if is_snap else "[OUR APP]"} {loc[:60]}')
