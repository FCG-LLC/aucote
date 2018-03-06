 # Scan stopping

 This document describes implementation and limitations of scan stopping.


 ## External

 When the `portdetection.{scan_name}.control.stop` is changed to `true` user expects that scan is going to be stopped.
 It should happen immediately, excepts task related to portscan. Scan will be stopped after obtain response on lately
 sent request. The scan will be taken to make differentiation with previous scan. It may be reason of potential issues.


 ## Implementation

 Every scan contains `ScanContext` which handle information about tasks related to given scan. If scan is cancelled,
 the `_cancelled` flag is set to `True` and all new tasks are skipped automatically and aren't put into task queue.

 If task has been processing already, the worker that handles it will be stopped.

 All tasks in queue are flagged as cancelled, and will be skipped as soon as worker get it from queue.