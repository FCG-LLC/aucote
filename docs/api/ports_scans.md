# Port scans

Obtains list of port scans from Aucote's storage. Port scan is a connection between port and scan.
Single port scan provides information about timestamp of scan of specific port.

### URL

```
/api/v1/ports?limit=<limit>&page=<page>
```

Parameters limit and offset are optional. Limit defines how many rows should be returned 
and page defines page of results. First page has number 0.

For parameters `limit=10`, `offset=3` the rows from 30 to 39 will be displayed.

### Request

```
curl "http://localhost:1235/api/v1/ports?limit=2&page=13"
```

### Response

```json
{
  "ports": [
    {
      "id": 4060,
      "url": "http://localhost:1235/api/v1/port/4060",
      "port": {
        "port_number": 3268,
        "protocol": "TCP",
        "node": {
          "id": 86,
          "ip": "10.12.2.175"
        }
      },
      "timestamp": 1508506247.2758377,
      "timestamp_human": "2017-10-20T13:30:47.275838+00:00",
      "scan": 966
    },
    {
      "id": 4059,
      "url": "http://localhost:1235/api/v1/port/4059",
      "port": {
        "port_number": 445,
        "protocol": "TCP",
        "node": {
          "id": 86,
          "ip": "10.12.2.175"
        }
      },
      "timestamp": 1508506247.2757692,
      "timestamp_human": "2017-10-20T13:30:47.275769+00:00",
      "scan": 966
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/ports?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/ports?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508831636.696856,
    "human_timestamp": "2017-10-24T07:53:56.696856+00:00"
  }
}
```

The most important section key is `ports` which contains list of port scans. 
For every port scan the keys presented below are available:

* id - scan identifier
* url - [url of port scan](port_scan.md)
* port - port object:
    * port_number - port number
    * protocol - port protocol
    * node
        * id - id of node
        * ip - ip address of node
* timestamp - timestamp of scan
* timestamp_human - date of scan
* scan - id of [scan](scan.md)