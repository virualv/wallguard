package main

import (
	"flag"
	"log"
	"os"

	"wallguard/internal/client"
	"wallguard/internal/config"
	"wallguard/internal/server"
)

var (
	configPath = flag.String("c", "config.yaml", "config file path")
	help       = flag.Bool("h", false, "show help")
)

func main() {
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard: %v\033[0m\n", err)
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		log.Fatalf("\033[1;31;40mWallGuard: config validation failed: %v\033[0m\n", err)
	}

	// 根据模式启动
	switch cfg.Mode {
	case "server":
		log.Println("WallGuard: Starting in server mode...")
		server.Run(&cfg.Server)
	case "client":
		log.Println("WallGuard: Starting in client mode...")
		client.Run(&cfg.Client)
	default:
		log.Fatalf("\033[1;31;40mWallGuard: unknown mode: %s\033[0m\n", cfg.Mode)
	}
}

func printUsage() {
	log.Println("WallGuard - Automatic IP whitelist management tool")
	log.Println()
	log.Println("Usage:")
	log.Println("  wallguard -c <config.yaml>")
	log.Println()
	log.Println("Options:")
	flag.PrintDefaults()
	log.Println()
	log.Println("Config file must specify 'mode' as 'server' or 'client'")
}
