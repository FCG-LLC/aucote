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
      "id": 22952,
      "url": "http://localhost:1235/api/v1/vulnerabilities/22952",
      "port": "10.12.2.202:623",
      "scan": {
        "id": 979,
        "url": "http://localhost:1235/api/v1/scans/979",
        "start": 1508512620,
        "start_human": "2017-10-20T15:17:00+00:00",
        "end": 1508512703.2486284,
        "end_human": "2017-10-20T15:18:23.248628+00:00",
        "protocol": "UDP",
        "scanner": "udp",
        "scanner_url": "http://localhost:1235/api/v1/scanners/udp"
      },
      "output": "asf-rmcp",
      "exploit": 0,
      "vuln_subid": 1,
      "time": 1508512709.0573323,
      "time_human": "2017-10-20T15:18:29.057332+00:00",
      "cvss": 0
    },
    {
      "id": 22951,
      "url": "http://localhost:1235/api/v1/vulnerabilities/22951",
      "port": "10.12.2.202:623",
      "scan": {
        "id": 976,
        "url": "http://localhost:1235/api/v1/scans/976",
        "start": 1508512371.8921125,
        "start_human": "2017-10-20T15:12:51.892112+00:00",
        "end": 1508512373.840704,
        "end_human": "2017-10-20T15:12:53.840704+00:00",
        "protocol": null,
        "scanner": "tools_basic",
        "scanner_url": "http://localhost:1235/api/v1/scanners/tools_basic"
      },
      "output": "None",
      "exploit": 0,
      "vuln_subid": 5,
      "time": 1508512603.9029918,
      "time_human": "2017-10-20T15:16:43.902992+00:00",
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
    "timestamp": 1508834112.218887,
    "human_timestamp": "2017-10-24T08:35:12.218887+00:00"
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
* time - vulnerability timestamp
* time_human - date of vulnerability finding
* cvss - cvss score
* exploit - exploit id
* vuln_subid - subidentifier of exploit

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
    "node": {
      "id": 25,
      "ip": "10.12.2.202"
    }
  },
  "scan": {
    "id": 16,
    "url": "http://localhost:1235/api/v1/scans/16",
    "start": 1508248380,
    "start_human": "2017-10-17T13:53:00+00:00",
    "end": 1508248462.0823298,
    "end_human": "2017-10-17T13:54:22.082330+00:00",
    "protocol": "UDP",
    "scanner": "udp",
    "scanner_url": "http://localhost:1235/api/v1/scanners/udp"
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
      "scanner": "tools_basic",
      "scanner_url": "http://localhost:1235/api/v1/scanners/tools_basic"
    },
    {
      "id": 982,
      "url": "http://localhost:1235/api/v1/scans/982",
      "start": 1508512860,
      "start_human": "2017-10-20T15:21:00+00:00",
      "end": 1508512941.3509648,
      "end_human": "2017-10-20T15:22:21.350965+00:00",
      "protocol": "UDP",
      "scanner": "udp",
      "scanner_url": "http://localhost:1235/api/v1/scanners/udp"
    }
  ],
  "meta": {
    "timestamp": 1508835340.5108466,
    "human_timestamp": "2017-10-24T08:55:40.510847+00:00"
  }
}
```

In the response the keys listed below are related to port scan details

* id - vulnerability identifier
* url - [url of vulnerability](vulnerability.md)
* port - port object
    * port_number - port number
    * protocol - port protocol
    * node
        * id - id of node
        * ip - ip address of node
* time - vulnerability timestamp
* time_human - date of vulnerability finding
* exploit - exploit id
* output - vulnerability description
* scan - [scan object](scans.md)
* scans - list of last scans (30) which found vulnerability. Scans are formatted like [scans](scans.md)
