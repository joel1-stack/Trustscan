import requests, re
base = 'https://trustscan.snapdeploy.dev'
session = requests.Session()

# Get login page
r = session.get(base + '/login', timeout=15)
content = r.text

# Check if this is a standard Django login or our custom login
if 'csrfmiddlewaretoken' in content:
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', content)
    csrf = match.group(1) if match else None
    print('Django CSRF token found:', csrf[:20] if csrf else 'No')
    
    payload = {
        'username': 'joelkaunda15@gmail.com',
        'password': 'Incorrect9.',
        'csrfmiddlewaretoken': csrf,
    }
    headers = {
        'X-CSRFToken': csrf,
        'Referer': base + '/login',
    }
    r = session.post(base + '/login', data=payload, headers=headers, timeout=15, allow_redirects=False)
    print(f'Django login: {r.status_code}')
    print(f'Location: {r.headers.get("location", "")}')
elif 'loginForm' in content:
    # Our custom login with JavaScript API
    print('Custom login form detected - will try API login')
    # Try the API login endpoint
    payload = {
        'email': 'joelkaunda15@gmail.com',
        'password': 'Incorrect9.',
    }
    r = session.post(base + '/api/auth/login/', json=payload, timeout=15, allow_redirects=False)
    print(f'API login: {r.status_code}')
    print(f'Response: {r.text[:300]}')
else:
    print('Unknown form type')
    print(content[3000:4000])
