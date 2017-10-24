# Node scan

Obtains node scan details for given id.

### URL

```
/api/v1/node/id
```

### Request

```
curl "http://localhost:1235/api/v1/node/77"
```

### Response

```json
{
  "id": 77,
  "url": "http://localhost:1235/api/v1/node/77",
  "node_id": 5,
  "ip": "10.12.2.210",
  "scan": 3,
  "scan_url": "http://localhost:1235/api/v1/scan/3",
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
      "id": 985,
      "url": "http://localhost:1235/api/v1/scan/985",
      "start": 1508513043,
      "start_human": "2017-10-20T15:24:03+00:00",
      "end": null,
      "end_human": null,
      "protocol": "UDP",
      "scanner": "udp",
      "scanner_url": "http://localhost:1235/api/v1/scanner/udp"
    }
  ],
  "meta": {
    "timestamp": 1508831230.6487832,
    "human_timestamp": "2017-10-24T07:47:10.648783+00:00"
  }
}
```

In the response the keys listed below are related to node scan details

* id - node scan id
* url - node scan url
* node_id - node id
* ip - node ip
* scan - scan id
* scan_url - url for scan details
* scans - list of last scans (30) performed on node. Scans are formatted like [scans](scans.md)
