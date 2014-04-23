AccelTCP
========

ACCELerate TCP proxy

Build
===

***Clone the code***
    
    $ git clone git://github.com/KLab/AccelTCP.git

***Build program***

    $ cd AccelTCP
    $ make

Note: This program requires OpenSSL libraries and libev.

Note: This program has been tested with Linux (kernel 2.6.32) and Mac OSX (10.9.2)

Usage
===
    usage: acceltcp [options] -- [tunnel_options] tunnel
      Options:
        -d, --debug                # debug mode
        -h, --help                 # show this message
        -q, --quiet                # quiet mode
        -v, --verbose              # verbose mode
        -V, --version              # show version
      Tunnel Options:
        -4, --ipv4only             # IPv4 only
        -6, --ipv6only             # IPv6 only
            --connection-num       # connection pool num (default: 1)
            --http                 # enable http mode
            --http-host=host       # http HOST header value
            --rbuf=size            # recieve socket buffer (default: system default)
            --sbuf=size            # send socket buffer (default: system default)
            --server               # enable server mode
            --ssl-accept           # enable SSL accept
            --ssl-certificate=file # SSL certificate file (default: ./server.crt)
            --ssl-privatekey=file  # SSL private-key file (default: ./server.key)
            --ssl-connect          # enable SSL connect
      Tunnel: (addr and port is numeric only)
        [local_addr:]local_port:remote_addr:remote_port

Example
===
***Server side proxy***

    [user@10.10.0.100]$ acceltcp -- --server --ssl-accept --ssl-connect 40381:133.242.5.116:443

***Client side proxy***

    [user@10.10.0.200]$ acceltcp -- --http --http-host=www.klab.com --ssl-accept --ssl-connect 8443:10.10.0.100:40381
