 # Scan stopping

 This document describes implementation and limitations of scan stopping.

 ## External

 When the `portdetection.{scan_name}.control.start` is changed to `true` user expects that scan is going to be stopped.
 It should happen immediately, excepts task related to portscan. Scan will be stopped after obtain response on lately
 sent request. The scan won't be taken for making differentiation with previous scan.

 ## Implementation

 Every scan contains `ScanContext` which handle information about tasks related to given scan. If scan is cancelled,
 the `_cancelled` flag is set to `True` and all new tasks are skipped automatically and don't put into task queue.

 If task is already working, the worker which handle it will be stopped.

 All tasks in queue are flag as cancelled, and will be skip as soon as worker get it from queue.