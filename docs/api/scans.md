# Scans

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
      "url": "http://localhost:1235/api/v1/scan/960",
      "start": 1508505840.933507,
      "start_human": "2017-10-20T13:24:00.933507+00:00",
      "end": 1508505847.5599566,
      "end_human": "2017-10-20T13:24:07.559957+00:00",
      "protocol": null,
      "scanner": "tools_basic",
      "scanner_url": "http://localhost:1235/api/v1/scanner/tools_basic"
    },
    {
      "id": 959,
      "url": "http://localhost:1235/api/v1/scan/959",
      "start": 1508505840,
      "start_human": "2017-10-20T13:24:00+00:00",
      "end": 1508505928.5188437,
      "end_human": "2017-10-20T13:25:28.518844+00:00",
      "protocol": "UDP",
      "scanner": "udp",
      "scanner_url": "http://localhost:1235/api/v1/scanner/udp"
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
* url - [url of scan](scan.md)
* start - timestamp of scan start
* start_human - date of scan start
* end - timestamp of scan end
* end_human - date of scan end
* protocol - protocol, for which the scan was performed
* scanner - scanner name
* scanner_url - [link to the scanner](scanner.md)