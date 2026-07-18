import requests
base = 'https://trustscan.snapdeploy.dev'
r = requests.get(base + '/login', timeout=15)
content = r.text
idx = content.find('document.getElementById("loginForm").addEventListener')
if idx > 0:
    block = content[idx:idx+2000]
    print(block)
