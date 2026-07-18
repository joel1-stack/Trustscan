import requests
base = 'https://trustscan.snapdeploy.dev'
headers = {'User-Agent': 'Mozilla/5.0'}

# Check if Load Balancer rewrites Location header
# Test: Django should redirect /about (no slash) -> /about/ (with slash)
r = requests.get(base + '/about', headers=headers, timeout=15, allow_redirects=False)
print(f'/about: {r.status_code} Location: {r.headers.get("location", "none")}')

# Test: /dashboard should redirect to LOGIN_URL (/auth/login/)
# If LOGIN_URL was changed, it should show /auth/login/ not /login
r = requests.get(base + '/dashboard', headers=headers, timeout=15, allow_redirects=False)
print(f'/dashboard: {r.status_code} Location: {r.headers.get("location", "none")}')

# Test: /auth/about (doesn't exist) to see 404 behavior
r = requests.get(base + '/auth/about', headers=headers, timeout=15, allow_redirects=False)
print(f'/auth/about: {r.status_code} Location: {r.headers.get("location", "none")}')
