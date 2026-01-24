package server

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// FirewallBackend represents the type of firewall backend
type FirewallBackend string

const (
	BackendIptables  FirewallBackend = "iptables"
	BackendFirewalld FirewallBackend = "firewalld"
	BackendUFW       FirewallBackend = "ufw"
)

// FirewallRule represents a firewall rule
type FirewallRule struct {
	SourceIP string
	Protocol string
	Ports    string
	Action   string
}

// FirewallManager interface defines methods for managing firewall rules
type FirewallManager interface {
	AddRule(rule FirewallRule) error
	DeleteRule(rule FirewallRule) error
	IsAvailable() bool
	GetBackend() FirewallBackend
}

// IptablesManager implements FirewallManager for iptables
type IptablesManager struct {
	ipt *iptables.IPTables
}

// NewIptablesManager creates a new iptables manager
func NewIptablesManager() (*IptablesManager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables instance: %v", err)
	}

	// Test if iptables is available
	if _, err = ipt.List("filter", "INPUT"); err != nil {
		return nil, fmt.Errorf("iptables not available: %v", err)
	}

	return &IptablesManager{ipt: ipt}, nil
}

func (im *IptablesManager) AddRule(rule FirewallRule) error {
	var ruleSpec []string

	if rule.SourceIP != "" {
		// IP-specific rule
		ruleSpec = []string{
			"-s", rule.SourceIP + "/32",
			"-p", rule.Protocol,
			"-m", "multiport",
			"--dports", rule.Ports,
			"-j", rule.Action,
		}
	} else {
		// Global rule (no source IP)
		ruleSpec = []string{
			"-p", rule.Protocol,
			"-m", "multiport",
			"--dports", rule.Ports,
			"-j", rule.Action,
		}
	}

	err := im.ipt.AppendUnique("filter", "INPUT", ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully added iptables rule: %s\033[0m\n", strings.Join(ruleSpec, " "))
	return nil
}

func (im *IptablesManager) DeleteRule(rule FirewallRule) error {
	var ruleSpec []string

	if rule.SourceIP != "" {
		// IP-specific rule
		ruleSpec = []string{
			"-s", rule.SourceIP + "/32",
			"-p", rule.Protocol,
			"-m", "multiport",
			"--dports", rule.Ports,
			"-j", rule.Action,
		}
	} else {
		// Global rule (no source IP)
		ruleSpec = []string{
			"-p", rule.Protocol,
			"-m", "multiport",
			"--dports", rule.Ports,
			"-j", rule.Action,
		}
	}

	err := im.ipt.DeleteIfExists("filter", "INPUT", ruleSpec...)
	if err != nil {
		if e, ok := err.(*iptables.Error); ok && e.IsNotExist() {
			log.Printf("\033[1;32;40mWallGuard [firewall]: iptables rule does not exist\033[0m\n")
			return nil
		}
		return fmt.Errorf("failed to delete iptables rule: %v", err)
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully deleted iptables rule: %s\033[0m\n", strings.Join(ruleSpec, " "))
	return nil
}

func (im *IptablesManager) IsAvailable() bool {
	return im.ipt != nil
}

func (im *IptablesManager) GetBackend() FirewallBackend {
	return BackendIptables
}

// FirewalldManager implements FirewallManager for firewalld
type FirewalldManager struct{}

// NewFirewalldManager creates a new firewalld manager
func NewFirewalldManager() (*FirewalldManager, error) {
	// Check if firewalld is available
	cmd := exec.Command("firewall-cmd", "--state")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("firewalld not available: %v", err)
	}

	return &FirewalldManager{}, nil
}

func (fm *FirewalldManager) AddRule(rule FirewallRule) error {
	// For firewalld, we use rich rules
	richRule := fmt.Sprintf("rule family=\"ipv4\" source address=\"%s\" port protocol=\"%s\" port=\"%s\" accept",
		rule.SourceIP, rule.Protocol, rule.Ports)

	cmd := exec.Command("firewall-cmd", "--permanent", "--add-rich-rule", richRule)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add firewalld rule: %v", err)
	}

	// Reload firewalld to apply changes
	cmd = exec.Command("firewall-cmd", "--reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload firewalld: %v", err)
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully added firewalld rule: %s\033[0m\n", richRule)
	return nil
}

func (fm *FirewalldManager) DeleteRule(rule FirewallRule) error {
	richRule := fmt.Sprintf("rule family=\"ipv4\" source address=\"%s\" port protocol=\"%s\" port=\"%s\" accept",
		rule.SourceIP, rule.Protocol, rule.Ports)

	cmd := exec.Command("firewall-cmd", "--permanent", "--remove-rich-rule", richRule)
	if err := cmd.Run(); err != nil {
		// Rule might not exist, which is fine
		log.Printf("\033[1;32;40mWallGuard [firewall]: firewalld rule does not exist or already removed\033[0m\n")
		return nil
	}

	// Reload firewalld to apply changes
	cmd = exec.Command("firewall-cmd", "--reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload firewalld: %v", err)
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully deleted firewalld rule: %s\033[0m\n", richRule)
	return nil
}

func (fm *FirewalldManager) IsAvailable() bool {
	cmd := exec.Command("firewall-cmd", "--state")
	return cmd.Run() == nil
}

func (fm *FirewalldManager) GetBackend() FirewallBackend {
	return BackendFirewalld
}

// UFWManager implements FirewallManager for UFW
type UFWManager struct{}

// NewUFWManager creates a new UFW manager
func NewUFWManager() (*UFWManager, error) {
	// Check if UFW is available
	cmd := exec.Command("ufw", "status")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("UFW not available: %v", err)
	}

	return &UFWManager{}, nil
}

func (um *UFWManager) AddRule(rule FirewallRule) error {
	// UFW command format: ufw allow from <source> to any port <port> proto <protocol>
	cmd := exec.Command("ufw", "allow", "from", rule.SourceIP, "to", "any", "port", rule.Ports, "proto", rule.Protocol)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add UFW rule: %v", err)
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully added UFW rule: from %s to any port %s proto %s\033[0m\n",
		rule.SourceIP, rule.Ports, rule.Protocol)
	return nil
}

func (um *UFWManager) DeleteRule(rule FirewallRule) error {
	// UFW delete command format: ufw delete allow from <source> to any port <port> proto <protocol>
	cmd := exec.Command("ufw", "delete", "allow", "from", rule.SourceIP, "to", "any", "port", rule.Ports, "proto", rule.Protocol)
	if err := cmd.Run(); err != nil {
		// Rule might not exist, which is fine
		log.Printf("\033[1;32;40mWallGuard [firewall]: UFW rule does not exist or already removed\033[0m\n")
		return nil
	}

	log.Printf("\033[1;32;40mWallGuard [firewall]: Successfully deleted UFW rule: from %s to any port %s proto %s\033[0m\n",
		rule.SourceIP, rule.Ports, rule.Protocol)
	return nil
}

func (um *UFWManager) IsAvailable() bool {
	cmd := exec.Command("ufw", "status")
	return cmd.Run() == nil
}

func (um *UFWManager) GetBackend() FirewallBackend {
	return BackendUFW
}

// NewFirewallManager creates a firewall manager based on the specified backend
func NewFirewallManager(backend FirewallBackend) (FirewallManager, error) {
	switch backend {
	case BackendIptables:
		return NewIptablesManager()
	case BackendFirewalld:
		return NewFirewalldManager()
	case BackendUFW:
		return NewUFWManager()
	default:
		return nil, fmt.Errorf("unsupported firewall backend: %s", backend)
	}
}

// AutoDetectFirewallBackend automatically detects the best available firewall backend
func AutoDetectFirewallBackend() FirewallBackend {
	// Try firewalld first (common on modern systems)
	if manager, err := NewFirewalldManager(); err == nil && manager.IsAvailable() {
		log.Printf("\033[1;34;40mWallGuard [firewall]: Auto-detected firewalld backend\033[0m\n")
		return BackendFirewalld
	}

	// Try UFW second (common on Ubuntu)
	if manager, err := NewUFWManager(); err == nil && manager.IsAvailable() {
		log.Printf("\033[1;34;40mWallGuard [firewall]: Auto-detected UFW backend\033[0m\n")
		return BackendUFW
	}

	// Fall back to iptables
	if manager, err := NewIptablesManager(); err == nil && manager.IsAvailable() {
		log.Printf("\033[1;34;40mWallGuard [firewall]: Auto-detected iptables backend\033[0m\n")
		return BackendIptables
	}

	log.Printf("\033[1;31;40mWallGuard [firewall]: No firewall backend available\033[0m\n")
	return ""
}
