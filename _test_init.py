import requests
base = 'https://trustscan.snapdeploy.dev'
r = requests.get(base + '/init', timeout=15, allow_redirects=False)
print(f'Init: {r.status_code}')
if r.status_code == 200:
    print(r.text[:500])
else:
    loc = r.headers.get('location', '')
    print(f'Location: {loc}')
