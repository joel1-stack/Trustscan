import requests, re, sys

def test():
    s = requests.Session()
    r = s.get('https://trustscan.vercel.app/login/', timeout=15)
    print(f'GET /login/: {r.status_code}')
    
    if 'OperationalError' in r.text or 'no such table' in r.text:
        print('DATABASE ERROR on login page')
        return False
    
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
    if not match:
        print('No CSRF token found')
        return False
    
    token = match.group(1)
    print(f'CSRF token obtained')
    
    r2 = s.post('https://trustscan.vercel.app/login/', data={
        'csrfmiddlewaretoken': token,
        'email': 'joelkaunda15@gmail.com',
        'password': 'Incorrect9.'
    }, headers={'Referer': 'https://trustscan.vercel.app/login/'}, timeout=15)
    
    print(f'POST /login/: {r2.status_code}')
    print(f'URL after: {r2.url}')
    
    if '/dashboard/' in r2.url:
        print('LOGIN SUCCESSFUL!')
        # Test dashboard loads
        r3 = s.get('https://trustscan.vercel.app/dashboard/', timeout=15)
        print(f'GET /dashboard/: {r3.status_code}')
        return True
    elif r2.status_code == 200:
        text_lower = r2.text.lower()
        if 'error' in text_lower or 'invalid' in text_lower:
            print('LOGIN FAILED - invalid credentials')
        elif 'operationalerror' in text_lower or 'no such table' in text_lower:
            print('DATABASE ERROR - Supabase not connected')
        else:
            print(f'Login page returned (length: {len(r2.text)})')
    return False

if __name__ == '__main__':
    success = test()
    sys.exit(0 if success else 1)
