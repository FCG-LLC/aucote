# Aucote - Automated Compliance Tests

Automated Compliance Tests is a service which is responsible for scanning network. First, it discovers open ports and next, it tries to find security vulnerabilities.

### Installation

##### Install prerequirements:
```
apt-get update
apt-get install git python3 python3-dev virtualenv -y
git clone https://github.com/FCG-LLC/aucote.git
```

#####Install nanomsg

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

Fulfill `aucote_cfg.yaml` with proper data.

### Usage

Aucote can be run as one-time scanner or service. It also can synchronize local exploits database with kudu

To run one-time scan you should run command from virtualenv:
```
python acucote.py run
```

To run as periodically service:
```
python acucote.py service
```

To synchronize exploits to database:
```
python aucote.py syncdb
```

### Contact

In case of any problem, please contact me!

Dominik Rosiek <<drosiek@collective-sense.com>>