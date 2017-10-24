# Node scans

## <a name="list">List</a>

Obtains list of node scans from Aucote's storage. Node scan is a connection between node and scan.
Single node scan provides information about timestamp of scan of specific node.

### URL

```
/api/v1/nodes?limit=<limit>&page=<page>
```

Parameters limit and offset are optional. Limit defines how many rows should be returned 
and page defines page of results. First page has number 0.

For parameters `limit=10`, `offset=3` the rows from 30 to 39 will be displayed.

### Request

```
curl "http://localhost:1235/api/v1/nodes?limit=2&page=13"
```

### Response

```json
{
  "nodes": [
    {
      "id": 27856,
      "url": "http://localhost:1235/api/v1/nodes/27856",
      "node_id": 315,
      "ip": "10.12.2.175",
      "scan": "tools_advanced"
    },
    {
      "id": 27855,
      "url": "http://localhost:1235/api/v1/nodes/27855",
      "node_id": 315,
      "ip": "10.12.1.159",
      "scan": "tools_advanced"
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/nodes?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/nodes?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508848085.2904274,
    "human_timestamp": "2017-10-24T12:28:05.290427+00:00"
  }
}
```

The most important section key is `nodes` which contains list of node scans. 
For every node scan the keys presented below are available:

* id - scan identifier
* url - [url of node scan](node_scans.md#details)
* node_id - identifier of node
* ip - ip address of node
* scan - name of scanner used by scan

## <a name="details">Details</a>

Obtains node scan details for given id.

### URL

```
/api/v1/nodes/<id>
```

### Request

```
curl "http://localhost:1235/api/v1/nodes/77"
```

### Response

```json
{
  "id": 77,
  "url": "http://localhost:1235/api/v1/nodes/77",
  "node_id": 5,
  "ip": "10.12.2.210",
  "scan": 3,
  "scan_url": "http://localhost:1235/api/v1/scans/3",
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
      "id": 985,
      "url": "http://localhost:1235/api/v1/scans/985",
      "start": 1508513043,
      "start_human": "2017-10-20T15:24:03+00:00",
      "end": null,
      "end_human": null,
      "protocol": "UDP",
      "scanner": "udp"
    }
  ],
  "meta": {
    "timestamp": 1508848148.3996565,
    "human_timestamp": "2017-10-24T12:29:08.399657+00:00"
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
