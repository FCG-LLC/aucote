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
      "id": 1213,
      "url": "http://localhost:1235/api/v1/scans/1213",
      "start": 1508843940.4868963,
      "start_human": "2017-10-24T11:19:00.486896+00:00",
      "end": 1508843940.579371,
      "end_human": "2017-10-24T11:19:00.579371+00:00",
      "protocol": null,
      "scanner": "tools_basic"
    },
    {
      "id": 1212,
      "url": "http://localhost:1235/api/v1/scans/1212",
      "start": 1508843932.125705,
      "start_human": "2017-10-24T11:18:52.125705+00:00",
      "end": 1508843932.5856252,
      "end_human": "2017-10-24T11:18:52.585625+00:00",
      "protocol": null,
      "scanner": "tools_advanced"
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/scans?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/scans?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508848480.084678,
    "human_timestamp": "2017-10-24T12:34:40.084678+00:00"
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

## <a name="details">Details</a>

Obtains scan details for given id.

### URL

```
/api/v1/scasn/<id>
```

### Request

```
curl "http://localhost:1235/api/v1/scans/78"
```

### Response

```json
{
  "scan": 78,
  "url": "http://localhost:1235/api/v1/scans/78",
  "start": 1508316960.7214646,
  "start_human": "2017-10-18T08:56:00.721465+00:00",
  "end": 1508316962.1886444,
  "end_human": "2017-10-18T08:56:02.188644+00:00",
  "nodes_scans": [
    {
      "id": 2703,
      "url": "http://localhost:1235/api/v1/nodes/2703",
      "node_id": 13,
      "ip": "10.12.2.100",
      "scan": "tools_basic"
    },
    {
      "id": 2702,
      "url": "http://localhost:1235/api/v1/nodes/2702",
      "node_id": 265,
      "ip": "10.12.2.203",
      "scan": "tools_basic"
    }
  ],
  "ports_scans": [
    {
      "id": 71,
      "url": "http://localhost:1235/api/v1/ports/71",
      "port": {
        "port_number": 623,
        "protocol": "UDP",
        "node": "10.12.2.202[25]"
      },
      "timestamp": 1508316962.1930747,
      "timestamp_human": "2017-10-18T08:56:02.193075+00:00",
      "scan": "tools_basic"
    }
  ],
  "meta": {
    "timestamp": 1508848387.6209805,
    "human_timestamp": "2017-10-24T12:33:07.620981+00:00"
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
* nodes_scans - list of node scans
* ports_scans - list of port scans