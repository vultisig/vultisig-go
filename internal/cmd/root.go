package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vultisig-cli",
	Short: "Vultisig CLI - Manage DKLS-based vaults",
	Long: `Vultisig CLI is a command-line tool for creating and managing 
DKLS-based cryptographic vaults. It connects to the Vultisig relay server
to coordinate multi-party key generation and stores vault metadata and 
keyshares locally in $HOME/.vultisig.`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug logging")
}

// initConfig initializes configuration
func initConfig() {
	// Set up logging
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if verbose, _ := rootCmd.PersistentFlags().GetBool("verbose"); verbose {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if debug, _ := rootCmd.PersistentFlags().GetBool("debug"); debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
}