import requests
base = 'https://trustscan.containers.snapdeploy.app'

# Test without redirect to see the actual response
r = requests.get(base + '/', timeout=15, allow_redirects=False)
print(f'/ (no redirect): {r.status_code}')
for k, v in r.headers.items():
    if k.lower() in ('location', 'server'):
        print(f'  {k}: {v}')

# Follow redirects up to 5
session = requests.Session()
session.max_redirects = 5
try:
    r = session.get(base + '/', timeout=15)
    print(f'/ (follow): {r.status_code} ({len(r.text)} bytes)')
except Exception as e:
    print(f'/ (follow): {type(e).__name__}: {e}')

# Test health endpoint
r = requests.get(base + '/health', timeout=15, allow_redirects=False)
print(f'/health (no redirect): {r.status_code}')
for k, v in r.headers.items():
    if k.lower() in ('location', 'server'):
        print(f'  {k}: {v}')
