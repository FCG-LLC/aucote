# Vulnerabilities

## <a name="list">List</a>

Obtains list of found vulnerabilities from Aucote's storage. Vulnerability is a result of security scan.

### URL

```
/api/v1/vulnerabilities?limit=<limit>&page=<page>
```

Parameters limit and offset are optional. Limit defines how many rows should be returned 
and page defines page of results. First page has number 0.

For parameters `limit=10`, `offset=3` the rows from 30 to 39 will be displayed.

### Request

```
curl "http://localhost:1235/api/v1/vulnerabilities?limit=2&page=13"
```

### Response

```json
{
  "vulnerabilitites": [
    {
      "id": 31413,
      "url": "http://localhost:1235/api/v1/vulnerabilities/31413",
      "port": "10.12.1.159:3000",
      "scan": {
        "id": 1237,
        "url": "http://localhost:1235/api/v1/scans/1237",
        "start": 1508844360.4904735,
        "start_human": "2017-10-24T11:26:00.490474+00:00",
        "end": 1508844360.6061676,
        "end_human": "2017-10-24T11:26:00.606168+00:00",
        "protocol": null,
        "scanner": "tools_advanced"
      },
      "output": "Default Request:\n    user_agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko",
      "exploit": 157,
      "vuln_subid": null,
      "time": 1508844921.275118,
      "time_human": "2017-10-24T11:35:21.275118+00:00",
      "cvss": 0
    },
    {
      "id": 31422,
      "url": "http://localhost:1235/api/v1/vulnerabilities/31422",
      "port": "10.12.1.159:3000",
      "scan": {
        "id": 1237,
        "url": "http://localhost:1235/api/v1/scans/1237",
        "start": 1508844360.4904735,
        "start_human": "2017-10-24T11:26:00.490474+00:00",
        "end": 1508844360.6061676,
        "end_human": "2017-10-24T11:26:00.606168+00:00",
        "protocol": null,
        "scanner": "tools_advanced"
      },
      "output": "Default Request:\n    user_agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko",
      "exploit": 157,
      "vuln_subid": null,
      "time": 1508844921.275118,
      "time_human": "2017-10-24T11:35:21.275118+00:00",
      "cvss": 0
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/vulnerabilities?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/vulnerabilities?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508848513.5876834,
    "human_timestamp": "2017-10-24T12:35:13.587683+00:00"
  }
}
```

The most important section key is `vulnerabilities` which contains list of vulnerabilities. 
For every vulnerability the keys presented below are available:

* id - vulnerability identifier
* url - [url of vulnerability](vulnerability.md)
* port - port in format `ip:port_number`
* scan - [scan object](scans.md)
* output - vulnerability description
* exploit - exploit id
* vuln_subid - subidentifier of exploit
* time - vulnerability timestamp
* time_human - date of vulnerability finding
* cvss - cvss score

## <a name="details">Details</a>

Obtains vulnerability details for given id.

### URL

```
/api/v1/vulnerabilities/id
```

### Request

```
curl "http://localhost:1235/api/v1/vulnerabilities/77"
```

### Response

```json
{
  "id": 77,
  "url": "http://localhost:1235/api/v1/sec_scans/77",
  "port": {
    "port_number": 623,
    "protocol": "UDP",
    "node": "10.12.2.202[25]"
  },
  "scan": {
    "id": 16,
    "url": "http://localhost:1235/api/v1/scans/16",
    "start": 1508248380,
    "start_human": "2017-10-17T13:53:00+00:00",
    "end": 1508248462.0823298,
    "end_human": "2017-10-17T13:54:22.082330+00:00",
    "protocol": "UDP",
    "scanner": "udp"
  },
  "time": 1508248467.9664423,
  "time_human": "2017-10-17T13:54:27.966442+00:00",
  "exploit": 0,
  "output": "None",
  "scans": [
    {
      "id": 986,
      "url": "http://localhost:1235/api/v1/scans/986",
      "start": 1508513043.0126145,
      "start_human": "2017-10-20T15:24:03.012614+00:00",
      "end": 1508513045.4429624,
      "end_human": "2017-10-20T15:24:05.442962+00:00",
      "protocol": null,
      "scanner": "tools_basic"
    },
    {
      "id": 982,
      "url": "http://localhost:1235/api/v1/scans/982",
      "start": 1508512860,
      "start_human": "2017-10-20T15:21:00+00:00",
      "end": 1508512941.3509648,
      "end_human": "2017-10-20T15:22:21.350965+00:00",
      "protocol": "UDP",
      "scanner": "udp"
    }
  ],
  "meta": {
    "timestamp": 1508848568.4928062,
    "human_timestamp": "2017-10-24T12:36:08.492806+00:00"
  }
}
```

In the response the keys listed below are related to port scan details

* id - vulnerability identifier
* url - url of vulnerability
* port - port object
    * port_number - port number
    * protocol - port protocol
    * node - node in format `ip[id]`
* scan - [scan object](scans.md)
* time - vulnerability timestamp
* time_human - date of vulnerability finding
* exploit - exploit id
* output - vulnerability description
* scans - list of last scans (30) which found vulnerability
