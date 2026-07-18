import requests
base = 'https://trustscan.snapdeploy.dev'
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

for path in ['/auth/login', '/auth/login/', '/about', '/dashboard', '/scan']:
    r = requests.get(base + path, headers=headers, timeout=15, allow_redirects=False)
    loc = r.headers.get('location', '')[:80]
    title = ''
    if '<title>' in r.text[:1000]:
        start = r.text.find('<title>')
        end = r.text.find('</title>')
        title = r.text[start+7:end]
    print(f'{path}: {r.status_code} {loc}')
    if title:
        print(f'  TITLE: {title}')
