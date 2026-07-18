import requests
base = 'https://trustscan.snapdeploy.dev'
r = requests.get(base + '/login', timeout=15)
content = r.text
# Search for API endpoints or fetch calls
for keyword in ['fetch(', 'axios.', '/api/', '/auth/', '/login']:
    idx = content.find(keyword)
    if idx > 0:
        print(f'--- Found {keyword} at {idx} ---')
        print(content[max(0,idx-100):idx+300])
        print()
