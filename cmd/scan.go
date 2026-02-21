package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"hyoketsu/db"
	"hyoketsu/scanner"

	"github.com/spf13/cobra"
)

var (
	jsonOutput    bool
	unknownOnly   bool
	dotnetOnly    bool
	dedup         bool
	hashOnly      bool
	filenameOnly  bool
	remoteURL     string
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Identify DLLs and JARs against the known database",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if remoteURL != "" {
			return scanRemote(args[0])
		}
		return scanLocal(args[0])
	},
}

func scanLocal(target string) error {
	store, err := db.Open(db.DefaultDBPath())
	if err != nil {
		return err
	}
	defer store.Close()

	results, err := scanner.Scan(store, target)
	if err != nil {
		return err
	}

	return displayResults(results)
}

// remoteLookupRequest mirrors the server's expected request body.
type remoteLookupRequest struct {
	Files []remoteLookupFile `json:"files"`
}

type remoteLookupFile struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
}

type remoteLookupResponse struct {
	Results []struct {
		Filename    string `json:"filename"`
		Status      string `json:"status"`
		MatchedBy   string `json:"matched_by"`
		Source      string `json:"source"`
		PackageName string `json:"package_name"`
	} `json:"results"`
	Stats struct {
		Known   int `json:"known"`
		Unknown int `json:"unknown"`
		Total   int `json:"total"`
	} `json:"stats"`
}

func remoteLookup(files []remoteLookupFile) (*remoteLookupResponse, error) {
	req := remoteLookupRequest{Files: files}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(remoteURL, "/") + "/lookup"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("remote lookup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}

	var lookupResp remoteLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&lookupResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &lookupResp, nil
}

func scanRemote(target string) error {
	files, err := scanner.CollectFiles(target)
	if err != nil {
		return err
	}

	// Hash everything and send with filenames — server does hash-first, filename-fallback
	req := make([]remoteLookupFile, len(files))
	results := make([]scanner.Result, len(files))
	for i := range files {
		scanner.HashFile(&files[i])
		req[i] = remoteLookupFile{
			Filename: strings.ToLower(files[i].Filename),
			Hash:     files[i].Hash,
			Type:     files[i].Type,
		}
		results[i] = scanner.Result{
			Filename: files[i].Filename,
			Path:     files[i].Path,
			Type:     files[i].Type,
			IsDotNet: files[i].IsDotNet,
			Hash:     files[i].Hash,
			Status:   "Unknown",
		}
	}

	resp, err := remoteLookup(req)
	if err != nil {
		return err
	}
	for i := range results {
		if i < len(resp.Results) {
			sr := resp.Results[i]
			results[i].Status = sr.Status
			results[i].MatchedBy = sr.MatchedBy
			results[i].Source = sr.Source
			results[i].PackageName = sr.PackageName
		}
	}

	// Dedup tracking
	seenHashes := make(map[string]bool)
	for i := range results {
		if results[i].Hash != "" {
			if seenHashes[results[i].Hash] {
				results[i].Duplicate = true
			} else {
				seenHashes[results[i].Hash] = true
			}
		}
	}

	return displayResults(results)
}

func displayResults(results []scanner.Result) error {
	// Apply filters
	var filtered []scanner.Result
	for _, r := range results {
		if unknownOnly && r.Status != "Unknown" {
			continue
		}
		if dotnetOnly && !r.IsDotNet {
			continue
		}
		if dedup && r.Duplicate {
			continue
		}
		if hashOnly && r.MatchedBy != "hash" {
			continue
		}
		if filenameOnly && r.MatchedBy != "filename" {
			continue
		}
		filtered = append(filtered, r)
	}
	results = filtered

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILENAME\tTYPE\tDOTNET\tSTATUS\tMATCHED\tSOURCE\tPACKAGE\tHASH")
	for _, r := range results {
		pkg := r.PackageName
		if pkg == "" {
			pkg = "-"
		}
		src := r.Source
		if src == "" {
			src = "-"
		}
		matched := "-"
		if r.MatchedBy != "" {
			matched = r.MatchedBy
		}
		dotnet := "-"
		if r.Type == "dll" {
			if r.IsDotNet {
				dotnet = "yes"
			} else {
				dotnet = "no"
			}
		}
		sha := "-"
		if r.Hash != "" {
			sha = r.Hash[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Filename, r.Type, dotnet, r.Status, matched, src, pkg, sha)
	}
	w.Flush()

	// Summary
	known, unknown := 0, 0
	for _, r := range results {
		if r.Status == "Known" {
			known++
		} else {
			unknown++
		}
	}
	fmt.Printf("\n%d known, %d unknown out of %d total files\n", known, unknown, known+unknown)
	return nil
}

func init() {
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&unknownOnly, "unknown-only", false, "Show only unknown files")
	scanCmd.Flags().BoolVar(&dotnetOnly, "dotnet-only", false, "Show only .NET assemblies")
	scanCmd.Flags().BoolVar(&dedup, "dedup", false, "Hide duplicate files (by SHA256 hash)")
	scanCmd.Flags().BoolVar(&hashOnly, "hash", false, "Show only hash-matched files")
	scanCmd.Flags().BoolVar(&filenameOnly, "filename", false, "Show only filename-matched files")
	scanCmd.Flags().StringVar(&remoteURL, "remote", "", "Remote server URL (e.g. http://host:8080)")
}
