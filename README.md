# Aucote - Automated Compliance Tests

Automated Compliance Tests is a service which is responsible for scanning network. First, it discovers open ports and next, it tries to find security vulnerabilities.

### Installation

##### Install prerequirements:
```
apt-get update
apt-get install git python3 python3-dev virtualenv -y
git clone https://github.com/FCG-LLC/aucote.git
```

##### Install nanomsg

Install nanomsg from sources (This should be done before next steps):
```
apt-get install cmake -y
wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz
tar xf 1.0.0.tar.gz
cd nanomsg-1.0.0/
mkdir build
cd build
cmake ..
make
make install
ldconfig
cd ../../
rm 1.0.0.tar.gz
rm -r nanomsg-1.00
```

##### Prepare environment:
```
cd aucote
virtualenv -p python3 venv
source venv/bin/activate # activate virtualenv
pip install -r requirements.txt
```

##### Install tools:
```
apt-get install nmap masscan skipfish hydra -y
```

### Configuration:

Copy example configuration:
```
cp aucote_cfg.yaml.exmaple aucote_cfg.yaml
```

Fulfill `aucote_cfg.yaml` - the most important fields are:
 - `topdis.api.host` and `topdis.api.port`, which define how to connect to Topdis 
 - `toucan.enable` - disable for local runs
 
You might also want to change `aucote_cfg_default.yaml` - important fields:
 - service.scans.parallel_tasks - defines how many threads should be run
 - portdetection.ports.tcp/udp.include - range of ports, it is good to keep small range for testing purposes
 - portdetection.scan_type - determines whether to use LIVE or PERIODIC scans
 - portdetection.port_scan_rate and - max number of packets/s for port scans. **This value should be set very carefully!**
 - portdetection.network_scan_rate - max number of packets/s for networks scans. **This value should be set very carefully!**
 - portdetection.networks - list of networks which are allowed/disabled to be scanned. **This value should be set very carefully!**
 - portdetection.periodic_scan.cron - cron-like scanning schedule **Time is always in UTC!**

More details and options are described in the files itself.

### Usage

Aucote can be run as one-time scanner or service. It also can synchronize local exploits database with kudu

To run one-time scan you should run command from virtualenv:
```
python acucote.py scan
```

To run as periodically service:
```
python acucote.py service
```

### Contact

In case of any problem, please contact me!

Dominik Rosiek <<drosiek@collective-sense.com>>