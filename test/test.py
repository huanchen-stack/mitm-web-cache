import subprocess
import time
import json
import os
import re

import threading

def stream_output(pipe):
    for line in iter(pipe.readline, b''):
        # print(line.strip())
        pass

def start_proxy():
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
    
    proxy_process = subprocess.Popen(
        ['python3', 'mitm-web-cache.py'],  # The script to run
        cwd=parent_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    threading.Thread(target=stream_output, args=(proxy_process.stdout,), daemon=True).start()
    threading.Thread(target=stream_output, args=(proxy_process.stderr,), daemon=True).start()

    return proxy_process

def stop_proxy(proxy_process):
    proxy_process.terminate()
    proxy_process.wait()
    print(proxy_process.pid, 'terminated')

def run_puppeteer(url, use_proxy=False, force_http1=False, sleep_time=10):
    command = ['node', 'start_chrome.js', '-u', url]
    if force_http1:
        command += ['-h', 'http1.1']
    else:
        command += ['-h', 'http2']
    if use_proxy:
        command += ['-p', '8090']

    result = subprocess.run(command, capture_output=True, text=True)
    # result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise Exception(f"Puppeteer error: {result.stderr}")

    resources = [json.loads(line) for line in result.stdout.splitlines()]
    return resources

def analyze_resources(resources_list):
    total_resources = len(resources_list)
    non_erroneous_resources = len([r for r in resources_list if r.get('statusCode')])
    resources_200 = len([r for r in resources_list if r.get('statusCode') == 200])
    resources_404 = len([r for r in resources_list if str(r.get('statusCode'))[0] in ['4', '5']])

    return total_resources, non_erroneous_resources, resources_200, resources_404

def sanitize_filename(url):
    url = url.lstrip("https://web.archive.org/web/")
    url = "".join([c for c in url if c.isalnum() or c in ['.', '/']])
    url = url.replace("/", "_")
    return url

def save_resource_to_file(url, resources, type):
    url = sanitize_filename(url)

    filepath = f"resources/{url}_{type}.json"
    with open(filepath, 'w') as f:
        json.dump(resources, f, indent=4)


def run_tests(url):
    filename = sanitize_filename(url)

    resources_1 = run_puppeteer(url, use_proxy=False, force_http1=False)
    analysis_1 = analyze_resources(resources_1)
    print(filename, "---1---", analysis_1, flush=True)
    save_resource_to_file(url, resources_1, type="1")
    time.sleep(10)

    resources_2 = run_puppeteer(url, use_proxy=False, force_http1=True)
    analysis_2 = analyze_resources(resources_2)
    print(filename, "---2---", analysis_2, flush=True)
    save_resource_to_file(url, resources_2, type="2")
    time.sleep(10)

    proxy_process = start_proxy()
    resources_3 = run_puppeteer(url, use_proxy=True, force_http1=False)
    analysis_3 = analyze_resources(resources_3)
    print(filename, "---3---", analysis_3, flush=True)
    save_resource_to_file(url, resources_3, type="3")
    stop_proxy(proxy_process)
    time.sleep(10)

    proxy_process = start_proxy()
    resources_4 = run_puppeteer(url, use_proxy=True, force_http1=False)
    analysis_4 = analyze_resources(resources_4)
    print(filename, "---4---", analysis_4, flush=True)
    save_resource_to_file(url, resources_4, type="4")
    stop_proxy(proxy_process)
    time.sleep(10)

with open("archived_links_2024.json", "r") as f:
    d = json.load(f)

# d = d[:1:]
print(d)

for url_to_test in d:
    # Test URL
    run_tests(url_to_test)

# start_proxy()
# time.sleep(100)