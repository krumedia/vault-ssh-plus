package cmd

import (
	"fmt"
	"github.com/isometry/vault-ssh-plus/agent"
	"github.com/isometry/vault-ssh-plus/openssh"
	"github.com/isometry/vault-ssh-plus/signer"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vssh",
	Short: "",
	Long:  "",
	Args:  cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getMatchingTargets(toComplete), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		processCommand(args)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	options struct {
		Signer  signer.Options
		OpenSSH openssh.Options `group:"OpenSSH ssh(1) Options" hidden:"yes"`
		Version func()          `long:"version" description:"Show version"`
	}
)

func showVersion() {
	fmt.Printf("vault-ssh-plus v%s (%s), %s\n", version, commit, date)
	os.Exit(0)
}

func init() {
	rootCmd.AddCommand(completionCmd)
	currentUser, _ := user.Current()
	rootCmd.PersistentFlags().StringVar(&options.Signer.Mode, "mode", "issue", "Mode")
	rootCmd.PersistentFlags().StringVar(&options.Signer.Type, "type", "ed25519", "Key type or preference for 'sign' mode")
	rootCmd.PersistentFlags().UintVar(&options.Signer.Bits, "bits", 256, "Key bits for 'issue' mode")
	rootCmd.PersistentFlags().StringVar(&options.Signer.Path, "path", "ssh", "Vault SSH mountpoint")
	rootCmd.PersistentFlags().StringVar(&options.Signer.Role, "role", "", "Vault SSH role (default: <ssh-username>@<hostname>)")
	rootCmd.PersistentFlags().UintVar(&options.Signer.TTL, "ttl", 30, "Vault SSH certificate TTL")
	rootCmd.PersistentFlags().StringVarP(&options.Signer.PublicKey, "public-key", "P",
		filepath.Join(currentUser.HomeDir, ".ssh/vssh_handler.pub"),
		"Path to preferred public key for 'sign' mode",
	)
}

func getMatchingTargets(toComplete string) []string {
	var vaultClient signer.Client
	var err error

	err = signer.Init(&vaultClient, options.Signer)
	if err != nil {
		log.Fatal(err)
	}
	allTargets := vaultClient.GetAllowedTargets()
	if toComplete == "" {
		return allTargets
	}
	var targets []string
	for _, target := range allTargets {
		if strings.HasPrefix(target, toComplete) {
			targets = append(targets, target)
		}
	}
	return targets
}

func processCommand(args []string) int {
	var (
		vaultClient signer.Client
		sshClient   openssh.Client
		err         error
	)

	err = signer.Init(&vaultClient, options.Signer)
	if err != nil {
		log.Fatal(err)
	}

	sshTarget := args[0]
	sshCommand := args[1:]

	if err := sshClient.Init(sshTarget); err != nil {
		log.Fatal("failed to parse ssh configuration: ", err)
	}

	roleDefaulted := defaultRole(&vaultClient, &sshClient)
	if roleDefaulted {
		log.Debugf("defaulted vault role to ssh username host combination: %s", sshClient.User+"@"+sshClient.Hostname)
	}

	userOverridden := overrideUser(&vaultClient, &sshClient)
	if userOverridden {
		log.Infof("ssh username overridden by vault role: %s", sshClient.User)
	}

	// if we already have a Control Connection, use it
	controlConnection := sshClient.ControlConnection()

	if !controlConnection && options.OpenSSH.ControlCommand != "exit" {
		updateRequestExtensions(&vaultClient.Options.Extensions, &sshClient.Extensions)

		log.Debugf("running in %q mode\n", vaultClient.Options.Mode)
		switch vaultClient.Options.Mode {
		case "issue":
			agent, err := agent.NewInternalAgent()
			if err != nil {
				log.Fatal("failed to start internal agent: ", err)
			}
			defer agent.Stop()

			privateKey, signedKey, err := vaultClient.GenerateSignedKeypair(sshClient.User)
			if err != nil {
				log.Fatal("failed to generate signed keypair: ", err)
			}

			if err := agent.AddSignedKeyPair(privateKey, signedKey); err != nil {
				log.Fatal("failed to add keypair to internal agent: ", err)
			}

			// override default ssh-agent socket
			os.Setenv("SSH_AUTH_SOCK", agent.SocketFile())
			log.Debugf("set SSH_AUTH_SOCK to %q\n", agent.SocketFile())
			if sshClient.ForceIdentityAgent {
				sshClient.PrependArgs([]string{"-o", "IdentityAgent=SSH_AUTH_SOCK"})
			}

		case "sign":
			signedKey, err := vaultClient.SignKey(sshClient.User + "@" + sshClient.Hostname)

			if err != nil {
				log.Fatal("failed to get signed key: ", err)
			}

			if err := sshClient.SetSignedKey(signedKey); err != nil {
				log.Fatal("invalid certificate: ", err)
			}

			certificateFile, err := sshClient.WriteCertificateFile()
			if err != nil {
				log.Fatal("failed to write signed key to file: ", err)
			}

			// ensure the signedKeyFile is deleted if we're killed
			setupExitHandler(certificateFile)
			defer os.Remove(certificateFile)

			sshClient.PrependArgs([]string{"-o", fmt.Sprintf("CertificateFile=%s", certificateFile)})
		}
	}

	log.WithFields(log.Fields{
		"ssh-args":                 sshClient.Args,
		"reuse-control-connection": controlConnection,
	}).Debug()

	if err := sshClient.Connect(sshTarget, sshCommand, controlConnection); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode()
		} else {
			return 999
		}
	}

	return 0
}

func setupExitHandler(fn string) {
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-s
		_ = os.Remove(fn)
		os.Exit(0)
	}()
}

func defaultRole(vaultClient *signer.Client, sshClient *openssh.Client) bool {
	// if role hasn't been set already, default to resolved SSH username@host combination
	// this is patched in our fork, upstream defaults to the user
	if vaultClient.Options.Role == "" {
		vaultClient.Options.Role = sshClient.User + "@" + sshClient.Hostname
		return true
	}
	return false
}

func overrideUser(vaultClient *signer.Client, sshClient *openssh.Client) bool {
	// if the role only allows a single, fixed user, use it
	if user := vaultClient.GetAllowedUser(); user != "" && sshClient.User != user {
		sshClient.User = user
		sshClient.PrependArgs([]string{"-l", user})
		return true
	}
	return false
}

func updateRequestExtensions(reqExt *signer.Extensions, sshExt *openssh.Extensions) {
	if !reqExt.AgentForwarding && sshExt.AgentForwarding {
		reqExt.AgentForwarding = true
	}

	if !reqExt.NoPTY && sshExt.NoPTY {
		reqExt.NoPTY = true
	}

	if !reqExt.PortForwarding && sshExt.PortForwarding {
		reqExt.PortForwarding = true
	}

	if !reqExt.X11Forwarding && sshExt.X11Forwarding {
		reqExt.X11Forwarding = true
	}
}
