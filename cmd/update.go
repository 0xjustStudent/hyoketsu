package cmd

import (
	"fmt"
	"sync"

	"hyoketsu/db"
	"hyoketsu/maven"
	"hyoketsu/nuget"

	"github.com/spf13/cobra"
)

var (
	workers   int
	skipNuget bool
	skipMaven bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Crawl NuGet and Maven Central catalogs and update the local database",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(db.DefaultDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		var wg sync.WaitGroup
		var nugetErr, mavenErr error

		// NuGet crawl — writes JSONL files to data/nuget/crawl/
		if !skipNuget {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cursor, err := store.GetCursor()
				if err != nil {
					nugetErr = fmt.Errorf("get nuget cursor: %w", err)
					return
				}
				if cursor != "" {
					fmt.Printf("[NuGet] Resuming from cursor: %s\n", cursor)
				} else {
					fmt.Println("[NuGet] Starting full catalog crawl...")
				}

				client := nuget.NewClient(store, workers)
				crawlDir := "data/nuget/crawl"
				newCursor, err := client.Crawl(cursor, crawlDir, func(page, total int) {
					if total == 0 {
						fmt.Println("[NuGet] Database is up to date.")
					}
				})
				if err != nil {
					fmt.Printf("[NuGet] Crawl stopped at cursor %s due to error: %v\n", newCursor, err)
					nugetErr = err
					return
				}
				fmt.Printf("[NuGet] Crawl complete. JSONL files in %s/\n", crawlDir)
			}()
		}

		// Maven crawl — downloads and parses the Lucene index
		if !skipMaven {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := maven.NewClient(store)
				if err := client.Crawl(func(count int) {}); err != nil {
					fmt.Printf("[Maven] Error: %v\n", err)
					mavenErr = err
				}
			}()
		}

		wg.Wait()

		if nugetErr != nil {
			return nugetErr
		}
		if mavenErr != nil {
			return mavenErr
		}

		total, _ := store.TotalCount()
		fmt.Printf("Done. %d entries in database.\n", total)
		return nil
	},
}

func init() {
	updateCmd.Flags().IntVar(&workers, "workers", 128, "Number of concurrent workers")
	updateCmd.Flags().BoolVar(&skipNuget, "skip-nuget", false, "Skip NuGet catalog crawl")
	updateCmd.Flags().BoolVar(&skipMaven, "skip-maven", false, "Skip Maven Central crawl")
}
