#SimpleTrans(Require Python3.3 or later)

This software transfer a file with high-level encryption. You just have to type 8-digits character on the receiving machine's display. 

Author: mipsparc(Twitter:@mipsparc, Web:https://mipsparc.net/, Mail:mipsparc@gmail.com)
License: The MIT License

##Required module
- Diffie-Hellman3 from https://gist.github.com/anonymous/11324965

##Before using
1. `wget https://gist.githubusercontent.com/anonymous/11324965/raw/DiffieHellman3.py`
1. Open 8095 UDP/TCP port(default) ex)Ubuntu `sudo ufw allow 8095`
1. `chmod 755 simpletrans.py`

##How to use
See `./simpletrans.py --help`  

###Easy example
- Receiver: `./simpletrans.py`
- Sender: `./simpletrans.py -s test.txt`

###Additional feature  
- Enable compress: `./simpletrans.py -s test.txt:bz2`
- Change port: `./simpletrans.py -p 8081` `./simpletrans.py -s test.txt -p 8081`

##TODO
- GUI
