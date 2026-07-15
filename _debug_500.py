import requests, re

s = requests.Session()

# Login
r = s.get('https://trustscan.vercel.app/login/', timeout=15)
m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
if m:
    token = m.group(1)
    r2 = s.post('https://trustscan.vercel.app/login/', data={
        'csrfmiddlewaretoken': token,
        'email': 'joelkaunda15@gmail.com',
        'password': 'Incorrect9.',
    }, headers={'Referer': 'https://trustscan.vercel.app/login/'}, timeout=15, allow_redirects=False)
    print('POST /login/:', r2.status_code, 'Location:', r2.headers.get('Location'))
    
    # Manually follow redirect (with session cookies)
    r3 = s.get('https://trustscan.vercel.app/dashboard/', timeout=15)
    print('GET /dashboard/:', r3.status_code, 'len:', len(r3.text))
    
    # Page title
    title_m = re.search(r'<title>([^<]+)</title>', r3.text)
    if title_m:
        print('Page title:', title_m.group(1))
    
    # Check for error messages
    for pattern in ['error', 'exception', 'traceback', '500', 'internal server']:
        if pattern in r3.text[:10000].lower():
            print(f'Found "{pattern}" in first 10k chars')
    
    # Show first 2000 chars
    print('--- First 2000 chars ---')
    print(r3.text[:2000])
    print('---')
    
    # Check if it's the login page being returned
    if 'Sign In' in r3.text and 'password' in r3.text.lower():
        print('Looks like login page - session not persisted')
    elif 'dashboard' in r3.text.lower() or 'Welcome' in r3.text:
        print('Looks like dashboard page - content found')
else:
    print('No CSRF token found')
    print(r.text[:2000])
