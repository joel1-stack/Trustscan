import requests
base = 'https://trustscan.containers.snapdeploy.app'
for url in ['/health', '/', '/login/', '/register/']:
    r = requests.get(base + url, timeout=15, allow_redirects=False)
    loc = r.headers.get('Location', '')
    print(f'{url}: {r.status_code} -> {loc[:80]}')
