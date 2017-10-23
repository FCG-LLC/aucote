# Scan

Obtains scan details for given id.

### URL

```
/api/v1/scan/id
```

### Request

```
curl "http://localhost:1235/api/v1/scan/77"
```

### Response

```json
{
  "scan": 78,
  "url": "http://localhost:1235/api/v1/scan/78",
  "start": 1508316960.7214646,
  "start_human": "2017-10-18T08:56:00.721465+00:00",
  "end": 1508316962.1886444,
  "end_human": "2017-10-18T08:56:02.188644+00:00",
  "nodes_scans": [
    {
      "id": 2703,
      "url": "http://localhost:1235/api/v1/node/2703",
      "node_id": 13,
      "ip": "10.12.2.100",
      "scan": 78,
      "scan_url": "http://localhost:1235/api/v1/scan/78"
    }
  ],
  "ports_scans": [
    {
      "id": 71,
      "url": "http://localhost:1235/api/v1/port/71",
      "port": {
        "port_number": 623,
        "protocol": "UDP",
        "node": {
          "id": 25,
          "ip": "10.12.2.202"
        }
      },
      "timestamp": 1508316962.1930747,
      "timestamp_human": "2017-10-18T08:56:02.193075+00:00",
      "scan": 78
    }
  ],
  "meta": {
    "timestamp": 1508742361.0702693,
    "human_timestamp": "2017-10-23T07:06:01.070269+00:00"
  }
}
```

In the response the 8 keys are related to scan details. This same format is used by [scan](scan.md) endpoint

* scan - scan id
* url - scan url
* start - timestamp of scan start
* start_human - date of scan start
* end - timestamp of scan end
* end_human - date of scan end
* nodes_scans - list of [node scans](nodes_scans.md)
* ports_scans - list of [port scans](ports_scans.md)
