import urllib.request
import re
import json
import random
import sys
import os

def fetch():
    try:
        req = urllib.request.Request("https://developer.android.com/about/versions", headers={'User-Agent': 'Mozilla/5.0'})
        versions_html = urllib.request.urlopen(req).read().decode('utf-8')
    except Exception as e:
        print("Failed to fetch versions:", e)
        return None, None
        
    known_versions = sorted(list(set(int(x) for x in re.findall(r'https://developer\.android\.com/about/versions/(\d+)', versions_html))), reverse=True)
    if not known_versions:
        print("No versions found")
        return None, None
    max_v = known_versions[0]
    versions = [max_v + 1] + known_versions

    for version in versions:
        try:
            req = urllib.request.Request(f"https://developer.android.com/about/versions/{version}", headers={'User-Agent': 'Mozilla/5.0'})
            latest_html = urllib.request.urlopen(req).read().decode('utf-8')
            qpr_matches = re.findall(r'href="(/about/versions/' + str(version) + r'/qpr(\d+)/download-ota)"', latest_html)
            if not qpr_matches:
                continue
            max_qpr = max(int(m[1]) for m in qpr_matches)
            qpr_path = [m[0] for m in qpr_matches if int(m[1]) == max_qpr][0]

            req = urllib.request.Request(f"https://developer.android.com{qpr_path}", headers={'User-Agent': 'Mozilla/5.0'})
            fi_html = urllib.request.urlopen(req).read().decode('utf-8')
            devices = []
            seen = set()
            for m in re.finditer(r'<tr id="([^"]+)">\s*<td[^>]*>([^<]+)</td>', fi_html, re.DOTALL):
                dev = m.group(1)
                if dev in seen: continue
                seen.add(dev)
                model = m.group(2).strip()
                model = re.sub(r'<[^>]+>', '', model).strip()
                devices.append({
                    "product": f"{dev}_beta",
                    "device": dev,
                    "model": model,
                    "version": version
                })
            
            if not devices:
                continue
            
            req = urllib.request.Request("https://flash.android.com", headers={'User-Agent': 'Mozilla/5.0'})
            flash_html = urllib.request.urlopen(req).read().decode('utf-8')
            api_key_m = re.search(r'AIza[0-9A-Za-z_-]{35}', flash_html)
            if not api_key_m:
                continue
            api_key = api_key_m.group(0)
            
            return devices, api_key
        except Exception as e:
            continue
    return None, None

devices, api_key = fetch()
if not devices:
    print("Failed to fetch devices")
    sys.exit(1)

dev = random.choice(devices)
req = urllib.request.Request(f"https://content-flashstation-pa.googleapis.com/v1/builds?product={dev['product']}&key={api_key}")
req.add_header("Referer", "https://flash.android.com")
req.add_header("X-Goog-Api-Key", api_key)
resp = urllib.request.urlopen(req).read().decode('utf-8')
data = json.loads(resp)
builds = data.get('flashstationBuild', [])

pif = None
for b in reversed(builds):
    meta = b.get('previewMetadata', {})
    if not meta.get('canary'): continue
    rc = b.get('releaseCandidateName', '')
    bid = b.get('buildId', '')
    if not rc or not bid: continue
    
    canary_id = meta.get('id', '')
    m = re.search(r'canary-(\d{4})(\d{2})', canary_id)
    if m:
        canary_month = f"{m.group(1)}-{m.group(2)}"
    else:
        canary_month = ""
    
    try:
        req = urllib.request.Request("https://source.android.com/docs/security/bulletin/pixel", headers={'User-Agent': 'Mozilla/5.0'})
        bulletin_html = urllib.request.urlopen(req).read().decode('utf-8')
        patch_m = re.search(rf'<td>({canary_month}-\d{{2}})</td>', bulletin_html)
        if patch_m:
            patch = patch_m.group(1)
        else:
            patch = f"{canary_month}-05"
    except:
        patch = f"{canary_month}-05"
    
    fingerprint = f"google/{dev['product']}/{dev['device']}:CANARY/{rc}/{bid}:user/release-keys"
    
    pif = {
        "MODEL": dev["model"],
        "MANUFACTURER": "Google",
        "FINGERPRINT": fingerprint,
        "SECURITY_PATCH": patch,
        "DEVICE_INITIAL_SDK_INT": "34"
    }
    break

if not pif:
    print("No canary build found")
    sys.exit(1)

os.makedirs('profile', exist_ok=True)
with open('profile/pif.json', 'w') as f:
    json.dump(pif, f, indent=2)
    f.write('\n')

print("Created profile/pif.json")
