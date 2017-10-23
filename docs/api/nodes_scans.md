# Node scans

Obtains list of node scans from Aucote's storage. Node scan is a connection between nodes and scans.
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
      "id": 27560,
      "url": "http://localhost:1235/api/v1/node/27560",
      "node_id": 96,
      "ip": "10.12.2.110",
      "scan": 986,
      "scan_url": "http://localhost:1235/api/v1/scan/986"
    },
    {
      "id": 27559,
      "url": "http://localhost:1235/api/v1/node/27559",
      "node_id": 18,
      "ip": "10.12.2.215",
      "scan": 986,
      "scan_url": "http://localhost:1235/api/v1/scan/986"
    }
  ],
  "navigation": {
    "limit": 2,
    "page": 13,
    "next_page": "http://localhost:1235/api/v1/nodes?limit=2&page=14",
    "previous_page": "http://localhost:1235/api/v1/nodes?limit=2&page=12"
  },
  "meta": {
    "timestamp": 1508742609.8040287,
    "human_timestamp": "2017-10-23T07:10:09.804029+00:00"
  }
}
```

The most important section key is `nodes` which contains list of node scans. 
For every node scan the keys presented below are available:

* id - scan identifier
* url - [url of node scan](node_scan.md)
* node_id - identifier of node
* ip - ip address of node
* scan - id of scan
* scan url - [url of scan](scan.md)