package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hyoketsu",
	Short: "Identify DLL and JAR files against a database of known .NET, NuGet, and Windows libraries",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(hashBackfillCmd)
	rootCmd.AddCommand(importCmd)
}
