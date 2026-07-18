import requests
base = 'https://trustscan.containers.snapdeploy.app'
for url in ['/health/', '/', '/login/', '/register/']:
    r = requests.get(base + url, timeout=15, allow_redirects=True)
    print(f'{url}: {r.status_code} ({len(r.text)} bytes, "healthy" in body: {"healthy" in r.text})')
