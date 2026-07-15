import requests, re
s = requests.Session()

# Test registration
r = s.get('https://trustscan.vercel.app/register/', timeout=15)
m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
if m:
    token = m.group(1)
    r2 = s.post('https://trustscan.vercel.app/register/', data={
        'csrfmiddlewaretoken': token,
        'name': 'Test User',
        'email': 'test@test.com',
        'password1': 'TestPass123!',
        'password2': 'TestPass123!',
    }, headers={'Referer': 'https://trustscan.vercel.app/register/'}, timeout=15, allow_redirects=False)
    print('POST /register/:', r2.status_code, 'Location:', r2.headers.get('Location'), 'len:', len(r2.text))
    title_m = re.search(r'<title>([^<]+)</title>', r2.text)
    if title_m:
        print('Page title:', title_m.group(1))
    print(r2.text[:2000])
else:
    print('No CSRF token')
    print(r.text[:2000])
