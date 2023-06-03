# WallGuard
An automatic add client ip to server firewall whitelist tool

## Dependence
 - iptables


### Server
- Run
```shell
./wallguard-server -bind 0.0.0.0 -cache-path /tmp/wg.cache -cert ./ssl/server.pem -key ./ssl/server.key -port 8443 -port-range 22,80:10000
```
- Get Help
```
./wallguard-server -h
```

### Client
- Run
```
./wallguard-client -ip 127.0.0.1 -port 2096 -cert ./ssl/client.pem -key ./ssl/client.key
```

- Get Help
```
./wallguard-client -h
```
