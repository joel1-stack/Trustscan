import requests
base = 'https://trustscan.snapdeploy.dev'

# Try different login payloads
session = requests.Session()

# 1. Try without turnstile
payload1 = {'email': 'joelkaunda15@gmail.com', 'password': 'Incorrect9.'}
r = session.post(base + '/api/auth/login', json=payload1, timeout=15)
print(f'No turnstile: {r.status_code} - {r.text[:100]}')

# 2. Try with empty turnstile
payload2 = {'email': 'joelkaunda15@gmail.com', 'password': 'Incorrect9.', 'turnstile': ''}
r = session.post(base + '/api/auth/login', json=payload2, timeout=15)
print(f'Empty turnstile: {r.status_code} - {r.text[:100]}')

# 3. Try with dummy turnstile
payload3 = {'email': 'joelkaunda15@gmail.com', 'password': 'Incorrect9.', 'turnstile': 'dummy'}
r = session.post(base + '/api/auth/login', json=payload3, timeout=15)
print(f'Dummy turnstile: {r.status_code} - {r.text[:100]}')

# 4. Try admin login endpoint
r = session.post(base + '/admin/login/', data={
    'username': 'joelkaunda15@gmail.com',
    'password': 'Incorrect9.',
    'csrfmiddlewaretoken': 'test',
    'next': '/admin/'
}, timeout=15, allow_redirects=False)
print(f'Admin login: {r.status_code} - Location: {r.headers.get("location", "")}')
