#SimpleTrans(Require Python3.3 or later)

This software transfer a file with high-level encryption. You just have to type 8-digits character on the receiving machine's display. 

Author: mipsparc(Twitter:@mipsparc, Web:https://mipsparc.net/, Mail:mipsparc@gmail.com)
License: The MIT License

##Required module
- Diffie-Hellman3 from https://gist.github.com/anonymous/11324965

##Before using
- `wget https://gist.githubusercontent.com/anonymous/11324965/raw/DiffieHellman3.py`
- Open 8095 UDP/TCP port
ex)Ubuntu `sudo ufw allow 8095`
- `chmod 755 simpletrans.py`

##How to use
See `./simpletrans.py --help`

##Issues
- Big files will eat whole your memory

##TODO
- GUI
