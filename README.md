#SimpleTrans(Require Python3.3 or later)

This software transfer a file with high-level encryption. You just have to type 8-digits number on the receiving machine's display. 

Author: mipsparc(Twitter:@mipsparc, Web:https://mipsparc.net/, Mail:mipsparc@gmail.com)
License: The MIT License

##Required module
- PyCrypto

##Before using
1. Open 8095 UDP/TCP port(default) ex)Ubuntu `sudo ufw allow 8095`
1. `chmod 755 simpletrans.py`

##How to use
See `./simpletrans.py --help`  

###Easy example
- Receiver: `./simpletrans.py`
- Sender: `./simpletrans.py --send test.txt`

###Additional feature  
- Enable compress: `./simpletrans.py -s test.txt:bz2`
- Change port: `./simpletrans.py -p 8081` `./simpletrans.py -s test.txt -p 8081`
- Change max segment numbers(If you have plenty of memory): `./simpletrans.py -s test.txt --maxsegment 5`

##TODO
- GUI
