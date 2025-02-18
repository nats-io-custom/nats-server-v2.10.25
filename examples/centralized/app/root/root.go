/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package root

import (
	"github.com/nats-io/nats-server/v2/examples/centralized/app/root/callout"
	cobra "github.com/spf13/cobra"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(cmd *cobra.Command) {
	cobra.CheckErr(cmd.Execute())
}

// ExecuteE adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteE(cmd *cobra.Command) error {
	return cmd.Execute()
}

// InitRootCmd initializes the root command
func InitRootCmd() *cobra.Command {
	// command represents the base command when called without any subcommands
	var command = &cobra.Command{
		Use:   "cli",
		Short: "A nats example integration tool",
		Long:  ``,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		// Uncomment the following line if your bare application
		// has an action associated with it:
		// Run: func(cmd *cobra.Command, args []string) { },

	}
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kafkaCLI.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	callout.Init(command)
	return command
}
