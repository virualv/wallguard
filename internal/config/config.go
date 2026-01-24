package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 统一配置结构
type Config struct {
	Mode   string       `yaml:"mode"` // "server" 或 "client"
	Server ServerConfig `yaml:"server"`
	Client ClientConfig `yaml:"client"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Bind string `yaml:"bind"`
	Port int    `yaml:"port"`
	SSL  struct {
		CertPath     string `yaml:"cert_path"`
		KeyPath      string `yaml:"key_path"`
		ClientCAPath string `yaml:"client_ca_path"`
	} `yaml:"ssl"`
	CacheDir   string   `yaml:"cache_dir"`
	OpenPorts  string   `yaml:"open_ports"`
	AllowUUIDs []string `yaml:"allow_uuids"`
	Firewall   struct {
		Backend string `yaml:"backend"` // "iptables", "firewalld", "ufw", or "auto"
	} `yaml:"firewall"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerIP   string `yaml:"server_ip"`
	ServerPort string `yaml:"server_port"`
	SSL        struct {
		SNI        string `yaml:"sni"`
		CertPath   string `yaml:"cert_path"`
		KeyPath    string `yaml:"key_path"`
		SkipVerify bool   `yaml:"skip_verify"`
	} `yaml:"ssl"`
	UUID       string `yaml:"uuid"`
	CheckIPURL string `yaml:"check_ip_url"`
	Interval   string `yaml:"interval"`
}

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.Mode != "server" && c.Mode != "client" {
		return fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", c.Mode)
	}

	if c.Mode == "server" {
		return c.validateServer()
	}
	return c.validateClient()
}

func (c *Config) validateServer() error {
	s := &c.Server
	if s.Bind == "" {
		return fmt.Errorf("server.bind is required")
	}
	if s.Port == 0 {
		return fmt.Errorf("server.port is required")
	}
	if s.SSL.CertPath == "" {
		return fmt.Errorf("server.ssl.cert_path is required")
	}
	if s.SSL.KeyPath == "" {
		return fmt.Errorf("server.ssl.key_path is required")
	}
	if s.SSL.ClientCAPath == "" {
		return fmt.Errorf("server.ssl.client_ca_path is required")
	}
	if s.CacheDir == "" {
		return fmt.Errorf("server.cache_dir is required")
	}
	if s.OpenPorts == "" {
		return fmt.Errorf("server.open_ports is required")
	}
	if len(s.AllowUUIDs) == 0 {
		return fmt.Errorf("server.allow_uuids is required")
	}
	return nil
}

func (c *Config) validateClient() error {
	cl := &c.Client
	if cl.ServerIP == "" {
		return fmt.Errorf("client.server_ip is required")
	}
	if cl.ServerPort == "" {
		return fmt.Errorf("client.server_port is required")
	}
	if cl.SSL.CertPath == "" {
		return fmt.Errorf("client.ssl.cert_path is required")
	}
	if cl.SSL.KeyPath == "" {
		return fmt.Errorf("client.ssl.key_path is required")
	}
	if cl.UUID == "" {
		return fmt.Errorf("client.uuid is required")
	}
	if cl.CheckIPURL == "" {
		return fmt.Errorf("client.check_ip_url is required")
	}
	if cl.Interval == "" {
		return fmt.Errorf("client.interval is required")
	}
	return nil
}
