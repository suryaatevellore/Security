# Reliable Netcat

This script aims to implement specific features of Linux's netcat module by using python for sending/recieving encrypted data. 

### Installation

The script requires Python 3.6.6, the installation files and instructions are provided here :
https://www.python.org/downloads/release/python-366/

### Running the script

```sh
usage: snc.py [-h] --key PASSWORD [-l] [destination] port

positional arguments:
  destination     Specify the Server IP Address
  port            Specify the server port

optional arguments:
  -h, --help      show this help message and exit
  --key PASSWORD  Enter the key value
  -l              Specify if the socket should be a listening socket
```

Server End:
```sh
$ python3.6 snc.py --key AWESOME -l 65432 < inputfile.txt > outfile.txt
```

Client End:
```sh
$ python3.6 snc.py --key AWESOME 127.0.0.1 65432 < inputfile.txt > outfile.txt
```

