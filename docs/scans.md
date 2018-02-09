 # Scans

 ## Chaining

 Every scan should contain `run_after` configuration key. It's a list containing names of scans which
 should be run after the scan finished. Scan will fire only if is enable. Basically listed conditions should be meet.

 ```
 portdetection.main_scan.run_after = ['chained_scan']
 portdetection.chained_scan.enable = True

 ```