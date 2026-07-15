import requests, re

s = requests.Session()

# Login
r = s.get('https://trustscan.vercel.app/login/', timeout=15)
m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
token = m.group(1)
r2 = s.post('https://trustscan.vercel.app/login/', data={
    'csrfmiddlewaretoken': token,
    'email': 'joelkaunda15@gmail.com',
    'password': 'Incorrect9.',
}, headers={'Referer': 'https://trustscan.vercel.app/login/'}, timeout=15, allow_redirects=False)

# Get dashboard
r3 = s.get('https://trustscan.vercel.app/dashboard/', timeout=15)

# Extract the traceback
# Find all the relevant sections
sections = re.split(r'<summary[^>]*>', r3.text)
for i, section in enumerate(sections):
    if 'ValueError' in section or 'FieldError' in section or 'Cannot resolve' in section or 'Traceback' in section:
        print(f'--- Section {i} ---')
        clean = re.sub(r'<[^>]+>', '', section)
        clean = clean.replace('&gt;', '>').replace('&lt;', '<').replace('&quot;', '"').replace('&amp;', '&')
        print(clean[:3000])
        print()

# Also look for the exception value
exc_match = re.search(r'<h2[^>]*>(.*?)</h2>', r3.text, re.DOTALL)
if exc_match:
    print('=== EXCEPTION VALUE ===')
    clean = re.sub(r'<[^>]+>', '', exc_match.group(1))
    clean = clean.replace('&gt;', '>').replace('&lt;', '<')
    print(clean.strip())

# Look for specific field error
field_match = re.search(r"Can't resolve keyword '(\w+)'", r3.text)
if field_match:
    print(f'\n=== FIELD ERROR: Cannot resolve keyword "{field_match.group(1)}" ===')

field_match2 = re.search(r"cannot be both deferred and joined", r3.text, re.IGNORECASE)
if field_match2:
    print(f'\n=== DEFERRED/JOINED ERROR ===')
