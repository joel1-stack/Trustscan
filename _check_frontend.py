import requests, re

r = requests.get('https://trustscan.vercel.app/', timeout=15)
links = re.findall(r'href="([^"]+)"', r.text)
print('All links on page:')
for l in sorted(set(links)):
    print(' ', l)

print()
print('Page length:', len(r.text))
print()

# Check for any broken Django references
if '{{' in r.text or '{%' in r.text:
    print('WARNING: Django template tags found!')
else:
    print('No Django template tags: OK')

# Check if links point to snapdeploy.dev
snap_links = [l for l in links if 'snapdeploy.dev' in l]
rel_links = [l for l in links if l.startswith('/')]
print(f'\nLinks to SnapDeploy: {len(snap_links)}')
print(f'Relative links: {len(rel_links)}')
for l in rel_links:
    print(f'  RELATIVE (should be snapdeploy): {l}')
