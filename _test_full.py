import requests, re, time

BASE = 'https://trustscan.vercel.app'

def test(step, path, desc):
    try:
        r = s.get(BASE + path, timeout=20)
        ok = r.status_code == 200
        print(f'  {"PASS" if ok else "FAIL"} [{r.status_code}] {desc}')
        return r
    except Exception as e:
        print(f'  FAIL [error] {desc}: {e}')
        return None

# 1. Init
s = requests.Session()
print('\n1. INIT')
test(1, '/init/', 'Init endpoint')

# 2. Login
print('\n2. LOGIN')
r = s.get(BASE + '/login/', timeout=15)
m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
if m:
    token = m.group(1)
    r2 = s.post(BASE + '/login/', data={
        'csrfmiddlewaretoken': token,
        'email': 'joelkaunda15@gmail.com',
        'password': 'Incorrect9.',
    }, headers={'Referer': BASE + '/login/'}, timeout=15, allow_redirects=False)
    print(f'  POST /login/: {r2.status_code} Location: {r2.headers.get("Location")}')
    if r2.status_code == 302:
        # Follow redirect
        r3 = s.get(BASE + '/dashboard/', timeout=15)
        print(f'  GET /dashboard/: {r3.status_code}')
        if r3.status_code == 200:
            if 'Welcome' in r3.text or 'Dashboard' in r3.text:
                print('  PASS Dashboard content verified')
            else:
                print(f'  FAIL Dashboard content: {r3.text[:300]}')
        else:
            title = re.search(r'<title>([^<]+)', r3.text)
            print(f'  ERROR: {title.group(1) if title else "unknown"}')
    else:
        print(f'  FAIL Login failed (stayed on login page)')
else:
    print('  FAIL No CSRF token')

# 3. Scan
print('\n3. SCAN')
r4 = s.get(BASE + '/scan/', timeout=15)
m2 = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r4.text)
if m2:
    token2 = m2.group(1)
    r5 = s.post(BASE + '/scan/', data={
        'csrfmiddlewaretoken': token2,
        'domain': 'example.com',
    }, headers={'Referer': BASE + '/scan/'}, timeout=30, allow_redirects=False)
    print(f'  POST /scan/: {r5.status_code} Location: {r5.headers.get("Location")}')
    if r5.status_code == 302:
        redirect_url = r5.headers.get('Location', '')
        r6 = s.get(BASE + redirect_url, timeout=15)
        print(f'  GET {redirect_url}: {r6.status_code}')
        if r6.status_code == 200:
            if 'pending' in r6.text.lower() or 'Scan' in r6.text:
                print('  PASS Results page loaded')
        else:
            title = re.search(r'<title>([^<]+)', r6.text)
            print(f'  ERROR: {title.group(1) if title else "unknown"}')
    else:
        print(f'  FAIL Scan submission: {r5.status_code}')
else:
    print('  FAIL No CSRF on scan page')

# 4. Check new pages
print('\n4. STATIC PAGES')
for page in ['/about/', '/privacy/', '/terms/', '/contact/']:
    r = s.get(BASE + page, timeout=15)
    print(f'  {"PASS" if r.status_code == 200 else "FAIL"} [{r.status_code}] {page}')

# 5. Registration
print('\n5. REGISTRATION')
s2 = requests.Session()
r = s2.get(BASE + '/register/', timeout=15)
m3 = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
if m3:
    token3 = m3.group(1)
    test_email = f'test_{int(time.time())}@test.com'
    r7 = s2.post(BASE + '/register/', data={
        'csrfmiddlewaretoken': token3,
        'name': 'Test User',
        'email': test_email,
        'password1': 'TestPass123!',
        'password2': 'TestPass123!',
    }, headers={'Referer': BASE + '/register/'}, timeout=15, allow_redirects=False)
    print(f'  POST /register/: {r7.status_code} Location: {r7.headers.get("Location")}')
    if r7.status_code == 302:
        r8 = s2.get(BASE + '/dashboard/', timeout=15)
        print(f'  GET /dashboard/: {r8.status_code} {"OK" if r8.status_code == 200 else "FAIL"}')
    else:
        print(f'  FAIL Registration failed')
else:
    print('  FAIL No CSRF on register')

print('\n=== ALL TESTS COMPLETE ===')
