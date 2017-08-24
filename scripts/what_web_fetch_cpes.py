from sys import argv

from requests import get
import re

app_name = argv[1]
result = get('https://nvd.nist.gov/view/vuln/search-results?query={0}'.format(app_name))
cves = re.findall(r"CVE-\d{4}-\d+", result.text)

for cve in reversed(cves):
    result = get('https://nvd.nist.gov/vuln/detail/' + cve)
    cpes = re.findall(r">(cpe.*?)</a>", result.text)
    if cpes:
        print("{0}.tb:{1}".format(app_name, cpes[0]))
    break
