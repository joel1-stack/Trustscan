import requests, json
base = 'https://trustscan.snapdeploy.dev'
session = requests.Session()

# Login
payload = {'email': 'joelkaunda15@gmail.com', 'password': 'Incorrect9.'}
r = session.post(base + '/api/auth/login', json=payload, timeout=15, allow_redirects=False)
print(f'Login response: {r.status_code}')
print(f'Body: {r.text[:500]}')

if r.status_code == 200:
    data = r.json()
    token = data.get('token') or data.get('access') or data.get('key')
    print(f'Token: {token[:50] if token else "None"}')
    
    # Create session from JWT
    if token:
        r2 = session.post(base + '/web/auth/session', json={'token': token}, timeout=15, allow_redirects=False)
        print(f'Session response: {r2.status_code}')
        print(f'Session body: {r2.text[:200]}')
        
        # Now try accessing the dashboard
        r3 = session.get(base + '/dashboard', timeout=15, allow_redirects=False)
        print(f'Dashboard: {r3.status_code}')
        
        # Try scan page
        r4 = session.get(base + '/scan', timeout=15, allow_redirects=False)
        print(f'Scan page: {r4.status_code}')
        if r4.status_code == 200:
            print(f'Scan page content (first 1000): {r4.text[:1000]}')
