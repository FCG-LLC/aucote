# Tasks

Returns list of tasks which are currently executing and queued.

### URL

```
/api/v1/tasks
```

### Request

```
curl "http://localhost:1235/api/v1/tasks"
```

### Response

#### Port scanner

```json
{
  "unfinished_tasks": 7,
  "queue": [
    "<scans.executor.Executor object at 0x7f7d063e6e80>",
    "<scans.executor.Executor object at 0x7f7d15407ef0>",
    "NmapPortInfoTask on 10.12.1.159:8865",
    "NmapPortInfoTask on 10.12.1.159:80"
  ],
  "workers": {
    "count": 3,
    "jobs": [
      "NmapPortScanTask on 10.12.2.175:445",
      "CVESearchServiceTask on 10.12.1.159:8865",
      "NmapPortScanTask on 10.12.1.159:80"
    ]
  }
}
```

Available keys:
* unfinished_tasks - number of tasks. It's sum of `currently executed` and `queued` tasks
* queue - list of tasks in queue
* workers - workers details
    * count - number of workers
    * jobs - list of tasks which are currently executing
