import requests

urls = [
    'https://trustscan.snapdeploy.dev/health',
    'https://trustscan.snapdeploy.dev/health/',
    'https://trustscan.snapdeploy.dev/',
    'https://trustscan.snapdeploy.dev/login/',
    'https://trustscan.snapdeploy.dev/register/',
    'https://trustscan.snapdeploy.dev/scan/',
    'https://trustscan.snapdeploy.dev/about/',
]

for url in urls:
    try:
        r = requests.get(url, timeout=10, allow_redirects=False)
        loc = ''
        if r.status_code in (301, 302):
            loc = f' -> {r.headers.get("Location")}'
        print(f'{url} -> {r.status_code} {len(r.text)}b{loc}')
    except Exception as e:
        print(f'{url} -> {type(e).__name__}: {e}')
