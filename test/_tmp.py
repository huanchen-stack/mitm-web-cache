import json

with open("resources/20241001112414_https__www.si.edu__1.json",  "r") as f:
    resources_http2 = json.load(f)
with open("resources/20241001112414_https__www.si.edu__4.json",  "r") as f:
    resources_http1 = json.load(f)

urls2 = set([r["url"] for r in resources_http2])
urls1 = set([r["url"] for r in resources_http1])

print(len(urls2 - urls1))
print(len(urls1 - urls2))

set2minus1 = urls2 - urls1
set2minus1 = list(set2minus1)
set1minus2 = urls1 - urls2
set1minus2 = list(set1minus2)

for i in range(len(set1minus2)):
    print(set1minus2[i])

print()
print()

for i in range(len(set2minus1)):
    print(set2minus1[i])
    # if i == 5:
    #     break