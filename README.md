# twistedshadowsocks

## a fun toy 

shadowsocks rewrite with python twisted 


## Test 

+ under ss python dir ,run *python local.py -s 127.0.0.1 -p 1234 -k fuckyou* as a test local proxy 
+ run the socat.sh to make a cat echo server or setup a httpd 
+ python tcp-proxy.py to setup the testing server
+ ./test_ss.sh to send test data through local socks5 proxy to the testing server,then maybe will print out the return data

