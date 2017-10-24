# Scans

## <a name="list">List</a>

Obtains list of scans from Aucote's storage.

### URL

```
/api/v1/scans?limit=<limit>&page=<page>
```

Parameters limit and offset are optional. Limit defines how many rows should be returned 
and page defines page of results. First page has number 0.

For parameters `limit=10`, `offset=3` the rows from 30 to 39 will be displayed.

### Request

```
curl "http://localhost:1235/api/v1/scans?limit=2&page=13"
```

### Response

```json
{
  "scans": [
    {
      "id": 960,
      "url": "http://localhost:1235/api/v1/scans/960",
      "start": 1508505840.933507,
      "start_human": "2017-10-20T13:24:00.933507+00:00",
      "end": 1508505847.5599566,
      "end_human": "2017-10-20T13:24:07.559957+00:00",
      "protocol": null,
      "scanner": "tools_basic",
      "scanner_url": "http://localhost:1235/api/v1/scanners/tools_basic"
    },
    {
      "id": 959,
      "url": "http://localhost:1235/api/v1/scans/959",
      "start": 1508505840,
      "start_human": "2017-10-20T13:24:00+00:00",
      "end": 1508505928.5188437,
      "end_human": "2017-10-20T13:25:28.518844+00:00",
      "protocol": "UDP",
      "scanner": "udp",
      "scanner_url": "http://localhost:1235/api/v1/scanners/udp"
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/scans?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/scans?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508741343.1024218,
    "human_timestamp": "2017-10-23T06:49:03.102422+00:00"
  }
}
```

The most important section key is `scans` which contains list of scans. 
For every scan the keys presented below are available:

* id - scan identifier
* url - [url of scan](scans.md)
* start - timestamp of scan start
* start_human - date of scan start
* end - timestamp of scan end
* end_human - date of scan end
* protocol - protocol, for which the scan was performed
* scanner - scanner name
* scanner_url - [link to the scanner](scanners.md)

## <a name="details">Details</a>

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

In the response the 8 keys are related to scan details. This same format is used by [scan](scans.md) endpoint

* scan - scan id
* url - scan url
* start - timestamp of scan start
* start_human - date of scan start
* end - timestamp of scan end
* end_human - date of scan end
* nodes_scans - list of [node scans](node_scans.md)
* ports_scans - list of [port scans](port_scans.md)