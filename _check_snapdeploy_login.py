import requests
base = 'https://trustscan.snapdeploy.dev'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}
r = requests.get(base + '/login', headers=headers, timeout=15, allow_redirects=False)
print(f'Status: {r.status_code}')
content = r.text[:2000]

if 'SnapDeploy' in content or 'snapdeploy' in content.lower():
    print('SERVING SNAPDEPLOY PAGE!')
elif 'loginForm' in content:
    print('SERVING OUR DJANGO LOGIN PAGE')
elif 'Sign In' in content:
    print('POSSIBLY our page')
else:
    print('UNKNOWN PAGE')

# Check title
title_start = content.find('<title>')
title_end = content.find('</title>')
if title_start >= 0 and title_end >= 0:
    print(f'TITLE: {content[title_start+7:title_end]}')
