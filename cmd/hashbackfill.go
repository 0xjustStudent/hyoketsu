package cmd

import (
	"fmt"

	"hyoketsu/db"
	"hyoketsu/nuget"

	"github.com/spf13/cobra"
)

var hashWorkers int

var hashBackfillCmd = &cobra.Command{
	Use:   "hash-backfill",
	Short: "Download nupkgs and compute SHA256 hashes for NuGet DLLs",
	Long:  "Reads crawl JSONL files from data/nuget/crawl/, downloads nupkgs, hashes DLLs, writes results to data/nuget/hashes/",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(db.DefaultDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		client := nuget.NewClient(store, hashWorkers)
		return client.HashBackfill("data/nuget/crawl", "data/nuget/hashes", func(done, total int) {
			fmt.Printf("[NuGet Hash] %d/%d packages\n", done, total)
		})
	},
}

func init() {
	hashBackfillCmd.Flags().IntVar(&hashWorkers, "workers", 128, "Number of concurrent workers")
}
