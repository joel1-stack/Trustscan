import requests, re, sys

BASE = 'https://trustscan.vercel.app'
s = requests.Session()

def test(method, path, desc, data=None, expect_status=None, expect_contains=None):
    url = BASE + path
    try:
        if method == 'GET':
            r = s.get(url, timeout=20)
        else:
            r = s.post(url, data=data, timeout=20)
        ok = True
        if expect_status and r.status_code not in expect_status:
            ok = False
        if expect_contains and expect_contains not in r.text:
            ok = False
        status_str = f'{r.status_code} ({len(r.text)}b)'
        print(f'  {"PASS" if ok else "FAIL"} [{status_str}] {desc} ({method} {path})')
        return r
    except Exception as e:
        print(f'  FAIL [error] {desc} ({method} {path}): {e}')
        return None

print('='*60)
print('TRUSTSCAN BUTTON/LINK TESTING')
print('='*60)

# 1. LANDING PAGE
print('\n--- Landing Page ---')
r = test('GET', '/', 'Homepage loads', expect_status={200})
if r:
    links_found = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', r.text):
        links_found.add(m.group(1))
    print(f'  Links found on page: {len(links_found)}')
    key_links = ['/scan/', '/login/', '/register/', '/api/', '/pricing/', '/features/', '/dashboard/', '#']
    for link in sorted(links_found):
        if link in key_links or link.startswith('/') and len(link) < 30:
            print(f'    - {link}')

# 2. KEY PAGES
print('\n--- Key Pages ---')
test('GET', '/scan/', 'Scan page', expect_status={200})
test('GET', '/login/', 'Login page', expect_status={200})
test('GET', '/register/', 'Register page', expect_status={200})
test('GET', '/api/', 'API page', expect_status={200, 404})
test('GET', '/pricing/', 'Pricing page', expect_status={200, 404})
test('GET', '/features/', 'Features page', expect_status={200, 404})

# 3. REGISTRATION FLOW
print('\n--- Registration ---')
r = test('GET', '/register/', 'Register form loads', expect_status={200})
if r:
    m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
    if m:
        token = m.group(1)
        test_username = f'testuser_{int(__import__("time").time())}'
        test_email = f'{test_username}@test.com'
        r2 = s.post(BASE + '/register/', data={
            'csrfmiddlewaretoken': token,
            'name': 'Test User',
            'email': test_email,
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
        }, headers={'Referer': BASE + '/register/'}, timeout=20)
        if r2.status_code in (200, 302):
            if '/login/' in r2.url or '/dashboard/' in r2.url:
                print(f'  PASS [{r2.status_code}] Registration successful -> {r2.url}')
            else:
                # Check for success message
                if 'success' in r2.text.lower() or 'verify' in r2.text.lower() or 'check' in r2.text.lower():
                    print(f'  PASS [{r2.status_code}] Registration submitted')
                else:
                    err = re.search(r'(?i)(error|alert|message)[^<]*<[^>]*>([^<]+)', r2.text[:3000])
                    err_text = err.group(2) if err else 'unknown'
                    print(f'  FAIL [{r2.status_code}] Registration: {err_text}')
                    # Print form content
                    form_errors = re.findall(r'<ul class="errorlist">(.*?)</ul>', r2.text, re.DOTALL)
                    for e in form_errors:
                        print(f'    Form error: {re.sub(r"<[^>]+>", "", e).strip()}')
        else:
            print(f'  FAIL [{r2.status_code}] Registration returned unexpected status')
    else:
        print('  FAIL No CSRF token on register page')

# 4. LOGIN FLOW
print('\n--- Login ---')
r = test('GET', '/login/', 'Login form loads', expect_status={200})
if r:
    m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
    if m:
        token = m.group(1)
        r2 = s.post(BASE + '/login/', data={
            'csrfmiddlewaretoken': token,
            'email': 'joelkaunda15@gmail.com',
            'password': 'Incorrect9.',
        }, headers={'Referer': BASE + '/login/'}, timeout=20)
        print(f'  {"PASS" if "/dashboard/" in r2.url else "FAIL"} [{r2.status_code}] Login -> {r2.url}')
        
        # 5. DASHBOARD
        print('\n--- Dashboard ---')
        r3 = test('GET', '/dashboard/', 'Dashboard loads (authenticated)', expect_status={200, 302})
        if r3 and r3.status_code == 200:
            if 'dashboard' in r3.text.lower() or 'Welcome' in r3.text:
                print('  PASS Dashboard content verified')
            else:
                print(f'  FAIL Dashboard content mismatch: {r3.text[:500]}')
        elif r3 and r3.status_code == 302:
            print(f'  FAIL Dashboard redirected (not authenticated): {r3.url}')

        # 6. SCAN FLOW
        print('\n--- Scan Flow ---')
        r4 = test('GET', '/scan/', 'Scan page (authenticated)', expect_status={200})
        if r4:
            m2 = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r4.text)
            if m2:
                token2 = m2.group(1)
                r5 = s.post(BASE + '/scan/', data={
                    'csrfmiddlewaretoken': token2,
                    'domain': 'example.com',
                }, headers={'Referer': BASE + '/scan/'}, timeout=30)
                if r5.status_code in (200, 302):
                    if '/scan/' in r5.url and r5.url != BASE + '/scan/':
                        print(f'  PASS [{r5.status_code}] Scan created -> {r5.url}')
                        # 7. RESULTS PAGE
                        r6 = test('GET', r5.url.replace(BASE, ''), 'Scan results page', expect_status={200})
                        if r6:
                            if 'pending' in r6.text.lower() or 'score' in r6.text.lower() or 'results' in r6.text.lower():
                                print('  PASS Results page content verified')
                            else:
                                print(f'  FAIL Results page content: {r6.text[:500]}')
                    else:
                        print(f'  FAIL [{r5.status_code}] Scan redirect unexpected: {r5.url}')
                        if r5.status_code == 200:
                            err = re.search(r'(?i)(error|alert)[^<]*<[^>]*>([^<]+)', r5.text[:3000])
                            err_text = err.group(2) if err else 'unknown'
                            print(f'    Error: {err_text}')
                else:
                    print(f'  FAIL [{r5.status_code}] Scan submission failed')
            else:
                print('  FAIL No CSRF on scan page')
    else:
        print('  FAIL No CSRF token on login page')

# 8. /init/ endpoint
print('\n--- Init Endpoint ---')
r = test('GET', '/init/', 'Init endpoint', expect_status={200})
if r:
    try:
        data = r.json()
        print(f'  Status: {data.get("status")}')
        log = data.get('log', '')
        for line in log.split('\n'):
            if line.strip():
                print(f'    {line.strip()}')
    except:
        print(f'  Raw: {r.text[:500]}')

print('\n' + '='*60)
print('TESTING COMPLETE')
print('='*60)
