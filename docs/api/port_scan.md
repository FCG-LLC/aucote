# Port scan

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
