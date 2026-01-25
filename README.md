# WallGuard

自动更新客户端 IP 到服务器防火墙白名单的工具。

## 特性

- 单一可执行文件，通过配置文件切换服务端/客户端模式
- 支持多种防火墙后端：iptables、firewalld、ufw
- 基于 mTLS 双向认证的安全通信
- 自动检测公网 IP 变化并更新防火墙规则

## 依赖

- Linux: iptables / firewalld / ufw (任选其一)

## 安装

```bash
# 编译
make build

# 或编译所有平台
make release
```

## 使用

### 服务端

1. 创建服务端配置文件 `server.yaml`:

```yaml
mode: "server"

server:
  bind: "0.0.0.0"
  port: 59876
  ssl:
    cert_path: "/etc/ssl/server.pem"
    key_path: "/etc/ssl/server.key"
    client_ca_path: "/etc/ssl/ca.pem"
  cache_dir: "/tmp/wallguard"
  open_ports: "22,80:90,443"
  allow_uuids:
    - "your-client-uuid-here"
  firewall:
    backend: "auto"
```

2. 启动服务端:

```bash
./wallguard -c server.yaml
```

### 客户端

1. 创建客户端配置文件 `client.yaml`:

```yaml
mode: "client"

client:
  server_ip: "your-server-ip"
  server_port: "59876"
  ssl:
    sni: "example.com"
    cert_path: "./client.crt"
    key_path: "./client.key"
    skip_verify: false
  uuid: "your-client-uuid-here"
  check_ip_url: "https://icanhazip.com/"
  interval: "180s"
```

2. 启动客户端:

```bash
./wallguard -c client.yaml
```

## 帮助

```bash
./wallguard -h
```

## 配置说明

完整配置示例请参考 [config.example.yaml](config.example.yaml)

### 服务端配置项

| 配置项 | 说明 |
|--------|------|
| `server.bind` | 监听地址 |
| `server.port` | 监听端口 |
| `server.ssl.cert_path` | 服务器证书路径 |
| `server.ssl.key_path` | 服务器私钥路径 |
| `server.ssl.client_ca_path` | 客户端 CA 证书路径 |
| `server.cache_dir` | IP 缓存目录 |
| `server.open_ports` | 开放端口范围，支持逗号分隔和范围格式 |
| `server.allow_uuids` | 允许的客户端 UUID 列表 |
| `server.firewall.backend` | 防火墙后端：`auto`/`iptables`/`firewalld`/`ufw` |

### 客户端配置项

| 配置项 | 说明 |
|--------|------|
| `client.server_ip` | 服务器 IP 地址 |
| `client.server_port` | 服务器端口 |
| `client.ssl.sni` | TLS SNI（可选） |
| `client.ssl.cert_path` | 客户端证书路径 |
| `client.ssl.key_path` | 客户端私钥路径 |
| `client.ssl.skip_verify` | 是否跳过服务器证书验证 |
| `client.uuid` | 客户端 UUID |
| `client.check_ip_url` | 公网 IP 查询地址 |
| `client.interval` | 更新间隔，支持 `ns`/`us`/`ms`/`s`/`m`/`h` |

## License

MIT
