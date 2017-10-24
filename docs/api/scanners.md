# Scanners

Returns list of current available scanners

### URL

```
/api/v1/scanners
```

### Request

```
curl "http://localhost:1235/api/v1/scanners"
```

### Response

```json
{
  "scanners": [
    {
      "name": "tcp",
      "url": "http://localhost:1235/api/v1/scanner/tcp"
    },
    {
      "name": "udp",
      "url": "http://localhost:1235/api/v1/scanner/udp"
    },
    {
      "name": "tools_basic",
      "url": "http://localhost:1235/api/v1/scanner/tools_basic"
    },
    {
      "name": "tools_advanced",
      "url": "http://localhost:1235/api/v1/scanner/tools_advanced"
    }
  ]
}
```

Response contains scanner name and url for more details