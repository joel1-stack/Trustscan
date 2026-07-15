import requests, re

s = requests.Session()

# Login first
r = s.get('https://trustscan.vercel.app/login/', timeout=15)
m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text)
token = m.group(1)
r2 = s.post('https://trustscan.vercel.app/login/', data={
    'csrfmiddlewaretoken': token,
    'email': 'joelkaunda15@gmail.com',
    'password': 'Incorrect9.',
}, headers={'Referer': 'https://trustscan.vercel.app/login/'}, timeout=15, allow_redirects=False)
print('Login:', r2.status_code)

# Get scan page
r3 = s.get('https://trustscan.vercel.app/scan/', timeout=15)
print('Scan page:', r3.status_code, len(r3.text))

# Submit scan
m2 = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r3.text)
token2 = m2.group(1)
r4 = s.post('https://trustscan.vercel.app/scan/', data={
    'csrfmiddlewaretoken': token2,
    'domain': 'example.com',
}, headers={'Referer': 'https://trustscan.vercel.app/scan/'}, timeout=30, allow_redirects=False)
print('Scan POST:', r4.status_code, 'Location:', r4.headers.get('Location'), 'len:', len(r4.text))

# Show error details
title_m = re.search(r'<title>([^<]+)</title>', r4.text)
if title_m:
    print('Title:', title_m.group(1))

# Extract full traceback
tb_match = re.search(r'<li class="frame[^>]*>.*?</li>', r4.text, re.DOTALL)
if tb_match:
    clean = re.sub(r'<[^>]+>', '', tb_match.group(0))
    print('Traceback frame:', clean[:1000])

# Find IntegrityError details
int_match = re.search(r'IntegrityError[^<]+', r4.text[:50000])
if int_match:
    clean = re.sub(r'<[^>]+>', '', int_match.group(0))
    print('IntegrityError:', clean[:500])

# Look for the exception value section
exc_value = re.search(r'<div id="summary">.*?<h2[^>]*>(.*?)</h2>', r4.text, re.DOTALL)
if exc_value:
    clean = re.sub(r'<[^>]+>', '', exc_value.group(1))
    print('Exception value:', clean.strip()[:1000])

# Find ALL text between certain markers
import html
for match in re.finditer(r'(IntegrityError|duplicate key|unique constraint|NOT NULL|null value)[^<]{0,200}', r4.text, re.I):
    clean = html.unescape(match.group(0))
    clean = re.sub(r'<[^>]+>', '', clean)
    print('Error context:', clean.strip()[:300])

# Also look for the specific error
for match in re.finditer(r'<pre class="exception_value">([^<]+)</pre>', r4.text):
    print('Exception value:', html.unescape(match.group(1)))

# Look for last frame in traceback
frames = re.findall(r'/var/task/[^"\']+', r4.text)
for f in frames[-5:]:
    print('Frame:', f)
