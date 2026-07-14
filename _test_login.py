import requests, re

s = requests.Session()
r = s.get('https://trustscan.vercel.app/login/', timeout=15)
print('GET /login/:', r.status_code)

m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
if not m:
    print('No CSRF token')
    exit(1)

token = m.group(1)
r2 = s.post('https://trustscan.vercel.app/login/', data={
    'csrfmiddlewaretoken': token,
    'email': 'joelkaunda15@gmail.com',
    'password': 'Incorrect9.'
}, headers={'Referer': 'https://trustscan.vercel.app/login/'}, timeout=15)

print('POST /login/:', r2.status_code)
print('URL:', r2.url)

if '/dashboard/' in r2.url:
    print('LOGIN SUCCESSFUL!')
    r3 = s.get('https://trustscan.vercel.app/dashboard/', timeout=15)
    print('GET /dashboard/:', r3.status_code, '(' + str(len(r3.text)) + ' bytes)')
else:
    print('LOGIN FAILED')
    if 'error' in r2.text.lower():
        import re
        err = re.search(r'class="[^"]*error[^"]*"[^>]*>([^<]+)', r2.text, re.I)
        if err:
            print('Error msg:', err.group(1))
