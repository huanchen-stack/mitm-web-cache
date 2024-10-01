import subprocess
import time
import json
import os
import re

import threading

def stream_output(pipe):
    for line in iter(pipe.readline, b''):
        print(line.strip())

def start_proxy():
    proxy_process = subprocess.Popen(
        ['python3', '../mitm-web-cache.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,  # Line-buffered output
        universal_newlines=True  # Automatically decode bytes to strings
    )
    # threading.Thread(target=stream_output, args=(proxy_process.stdout,), daemon=True).start()
    # threading.Thread(target=stream_output, args=(proxy_process.stderr,), daemon=True).start()
    return proxy_process

def stop_proxy(proxy_process):
    proxy_process.terminate()
    proxy_process.wait()

def run_puppeteer(url, use_proxy=False, force_http1=False):
    command = ['node', 'start_chrome.js', '-u', url]

    if force_http1:
        command += ['-h', 'http1.1']
    else:
        command += ['-h', 'http2']

    if use_proxy:
        command += ['-p', '8080']

    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Puppeteer error: {result.stderr}")

    resources = [json.loads(line) for line in result.stdout.splitlines()]
    return resources

def analyze_resources(resources_list):
    total_resources = len(resources_list)
    non_erroneous_resources = len([r for r in resources_list if r.get('statusCode')])
    resources_200 = len([r for r in resources_list if r.get('statusCode') == 200])
    resources_404 = len([r for r in resources_list if r.get('statusCode') == 404])

    return total_resources, non_erroneous_resources, resources_200, resources_404

def sanitize_filename(url):
    sanitized_name = re.sub(r'\W+', '_', url)
    return sanitized_name

def save_resources_to_file(filename, stats, resources_1, resources_2, resources_3, resources_4):
    data = {
        'stats': stats,
        'resources_1': resources_1,
        'resources_2': resources_2,
        'resources_3': resources_3,
        'resources_4': resources_4
    }
    
    os.makedirs('resources', exist_ok=True)
    
    filepath = os.path.join('resources', filename)
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def run_tests(url):
    
    resources_1 = run_puppeteer(url, use_proxy=False, force_http1=False)
    resources_2 = run_puppeteer(url, use_proxy=False, force_http1=True)
    
    proxy_process = start_proxy()
    resources_3 = run_puppeteer(url, use_proxy=True, force_http1=False)
    stop_proxy(proxy_process)
    
    proxy_process = start_proxy()
    resources_4 = run_puppeteer(url, use_proxy=True, force_http1=False)
    stop_proxy(proxy_process)


    analysis_1 = analyze_resources(resources_1)
    analysis_2 = analyze_resources(resources_2)
    analysis_3 = analyze_resources(resources_3)
    analysis_4 = analyze_resources(resources_4)

    stats = {
        'total_resources': (analysis_1[0], analysis_2[0], analysis_3[0], analysis_4[0]),
        'non_erroneous_resources': (analysis_1[1], analysis_2[1], analysis_3[1], analysis_4[1]),
        'resources_200': (analysis_1[2], analysis_2[2], analysis_3[2], analysis_4[2]),
        'resources_404': (analysis_1[3], analysis_2[3], analysis_3[3], analysis_4[3])
    }

    sanitized_filename = sanitize_filename(url) + ".json"
    
    save_resources_to_file(sanitized_filename, stats, resources_1, resources_2, resources_3, resources_4)
    
    return stats

with open("archived_links_2024.json", "r") as f:
    d = json.load(f)

for host, url_to_test in d.items():
    # Test URL
    results = run_tests(url_to_test)
    print(results, flush=True)
    time.sleep(60)

# start_proxy()
# time.sleep(100)