# Security scan

Obtains security scan details for given id.

### URL

```
/api/v1/sec_scan/id
```

### Request

```
curl "http://localhost:1235/api/v1/sec_scan/12483"
```

### Response

```json
{
  "id": 12483,
  "url": "http://localhost:1235/api/v1/sec_scan/12483",
  "port": {
    "port_number": 5985,
    "protocol": "TCP",
    "node": {
      "id": 86,
      "ip": "10.12.2.175"
    }
  },
  "scan": {
    "id": 942,
    "url": "http://localhost:1235/api/v1/scan/942",
    "start": 1508504400.6845937,
    "start_human": "2017-10-20T13:00:00.684594+00:00",
    "end": 1508504411.276814,
    "end_human": "2017-10-20T13:00:11.276814+00:00",
    "protocol": null,
    "scanner": "tools_advanced",
    "scanner_url": "http://localhost:1235/api/v1/scanner/tools_advanced"
  },
  "scan_end": 1508505422,
  "scan_end_human": "2017-10-20T13:17:02+00:00",
  "scan_start": 1508504395.823977,
  "scan_start_human": "2017-10-20T12:59:55.823977+00:00",
  "exploit": {
    "id": 72,
    "app": "nmap",
    "name": "http-vuln-cve2011-3192"
  },
  "scan_url": "http://localhost:1235/api/v1/scan/942",
  "scans": [
    {
      "id": 942,
      "url": "http://localhost:1235/api/v1/scan/942",
      "start": 1508504400.6845937,
      "start_human": "2017-10-20T13:00:00.684594+00:00",
      "end": 1508504411.276814,
      "end_human": "2017-10-20T13:00:11.276814+00:00",
      "protocol": null,
      "scanner": "tools_advanced",
      "scanner_url": "http://localhost:1235/api/v1/scanner/tools_advanced"
    },
    {
      "id": 931,
      "url": "http://localhost:1235/api/v1/scan/931",
      "start": 1508503680.2786627,
      "start_human": "2017-10-20T12:48:00.278663+00:00",
      "end": 1508503687.3294709,
      "end_human": "2017-10-20T12:48:07.329471+00:00",
      "protocol": null,
      "scanner": "tools_basic",
      "scanner_url": "http://localhost:1235/api/v1/scanner/tools_basic"
    }
  ],
  "meta": {
    "timestamp": 1508833683.8892133,
    "human_timestamp": "2017-10-24T08:28:03.889213+00:00"
  }
}
```

In the response the keys listed below are related to port scan details

* id - port scan id
* url - port scan url
* port - port object
    * port_number - port number
    * protocol - port protocol
    * node
        * id - id of node
        * ip - ip address of node
* timestamp - timestamp of scan
* timestamp_human - date of scan
* scan - [scan object](scans.md)
* scan_url - url of [scan](scan.md)
* scan_end - security scan end timestamp
* scan_end_human - date of security  scan end
* scan_start - security scan start timestamp
* scan_start_human - date of security scan start
* exploit - exploit object
    * id - id of exploit
    * app - name of exploit app
    * name - name of script
* scans - list of last scans (30) performed on port for given exploit. Scans are formatted like [scans](scans.md)
