 # Throttling

 Depends on `service.scans/task_politic` aucote could have different behaviour regarding to throttling.

 Given key can take one of four arguments

 - `0` - Close only idle workers
 - `1` - Kill working workers firstly and close idle workers
 - `2` - Kill working and idle workers proportionally to `throttling.rate` change 
 - `3` - Close idle workers and if it's not enough kill working workers
 
 ## Examples
 
 ### 0
 
 ```
 maximum workers number: 100
 
 throttling.rate: 0.8 -> 0.2
 current workers number: 80 -> 20
 
 working workers: 40 -> 40 # The 20 will be closed after finishing its task
 idle workers: 40 -> 0
 ```
 
 ### 1
 
 ```
 maximum workers number: 100
 
 throttling.rate: 0.8 -> 0.6
 current workers number: 80 -> 60
 
 working workers: 40 -> 20
 idle workers: 40 -> 40
 ```
 
 ### 2
 
 ```
 maximum workers number: 100
 
 throttling.rate: 0.8 -> 0.6
 current workers number: 80 -> 60
 
 working workers: 40 -> 30
 idle workers: 40 -> 30
 ```
 
 ### 4
 
 ```
 maximum workers number: 100
 
 throttling.rate: 0.8 -> 0.2
 current workers number: 80 -> 20
 
 working workers: 40 -> 20
 idle workers: 40 -> 0
 ```
 