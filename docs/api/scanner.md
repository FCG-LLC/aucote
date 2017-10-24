# Scanner

Obtains details about specific scanner

### URL

```
/api/v1/scanner/<name>
```

### Request

```
curl "http://localhost:1235/api/v1/scanner/tcp"
```

### Response

#### Port scanner

```json
{
  "scan": "tcp",
  "current_scan": 1508839167,
  "previous_scan": 1508839080,
  "next_scan": 1508839200,
  "scanners": {
    "IPv4": [
      "masscan"
    ],
    "IPv6": [
      "nmap"
    ]
  },
  "status": "IN PROGRESS",
  "nodes": [
    "10.12.1.159[315]",
    "10.12.2.175[315]"
  ]
}
```

Keys listed below:
* scan - scanner name
* current_scan - timestamp of current scan
* previous_scan - timestamp of previous scan (by cron)
* next_scan - timestamp of next scan (by cron)
* scanners:
    * IPv4 - list of IPv4 port scanners
    * IPv6 - list of IPv6 port scanners
* status - status of scan `IN PROGRESS` or `IDLE`
* nodes - list of nodes in format `ip[id]`

#### Tools scanner

Not implemented yet