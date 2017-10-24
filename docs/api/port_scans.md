# Port scans

## <a name="list">List</a>

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
* url - [url of port scan](port_scans.md#details)
* port - port object:
    * port_number - port number
    * protocol - port protocol
    * node
        * id - id of node
        * ip - ip address of node
* timestamp - timestamp of scan
* timestamp_human - date of scan
* scan - id of [scan](scans.md#details)

## <a name="details">Details</a>

Obtains port scan details for given id.

### URL

```
/api/v1/port/id
```

### Request

```
curl "http://localhost:1235/api/v1/port/77"
```

### Response

```json
{
  "id": 77,
  "url": "http://localhost:1235/api/v1/port/77",
  "timestamp": 1508317322.1307728,
  "human_timestamp": "2017-10-18T09:02:02.130773+00:00",
  "port_number": 623,
  "protocol": "UDP",
  "node": {
    "id": 25,
    "ip": "10.12.2.202"
  },
  "scan": 93,
  "scan_url": "http://localhost:1235/api/v1/scan/93",
  "scans": [
    {
      "id": 986,
      "url": "http://localhost:1235/api/v1/scan/986",
      "start": 1508513043.0126145,
      "start_human": "2017-10-20T15:24:03.012614+00:00",
      "end": 1508513045.4429624,
      "end_human": "2017-10-20T15:24:05.442962+00:00",
      "protocol": null,
      "scanner": "tools_basic",
      "scanner_url": "http://localhost:1235/api/v1/scanner/tools_basic"
    },
    {
      "id": 982,
      "url": "http://localhost:1235/api/v1/scan/982",
      "start": 1508512860,
      "start_human": "2017-10-20T15:21:00+00:00",
      "end": 1508512941.3509648,
      "end_human": "2017-10-20T15:22:21.350965+00:00",
      "protocol": "UDP",
      "scanner": "udp",
      "scanner_url": "http://localhost:1235/api/v1/scanner/udp"
    }
  ],
  "meta": {
    "timestamp": 1508832075.0708394,
    "human_timestamp": "2017-10-24T08:01:15.070839+00:00"
  }
}
```

In the response the keys listed below are related to port scan details

* id - port scan id
* url - port scan url
* timestamp - timestamp of scan
* timestamp_human - date of scan
* port_number - port number
* protocol - port protocol
* node
    * id - id of node
    * ip - ip address of node
* scan - scan id
* scan_url - url for scan details
* scans - list of last scans (30) performed on port. Scans are formatted like [scans](scans.md)
