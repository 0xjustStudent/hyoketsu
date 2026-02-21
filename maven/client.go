package maven

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hyoketsu/db"
)

const (
	indexURL      = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"
	batchSize     = 5000
)

type Client struct {
	store *db.Store
}

func NewClient(store *db.Store) *Client {
	return &Client{store: store}
}

// Crawl downloads the Maven Central Lucene index and parses it directly.
// Each record with a JAR packaging and SHA1 hash is inserted into the DB.
func (c *Client) Crawl(progress func(count int)) error {
	// Download index to temp file
	indexPath, err := c.downloadIndex(progress)
	if err != nil {
		return fmt.Errorf("download index: %w", err)
	}
	defer os.Remove(indexPath)

	// Parse index
	return c.parseIndex(indexPath, progress)
}

func (c *Client) downloadIndex(progress func(count int)) (string, error) {
	fmt.Println("[Maven] Downloading Lucene index...")

	resp, err := http.Get(indexURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", indexURL, resp.StatusCode)
	}

	tmpDir := filepath.Join(os.TempDir(), "hyoketsu")
	os.MkdirAll(tmpDir, 0755)
	tmpFile := filepath.Join(tmpDir, "maven-index.gz")

	f, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}

	totalSize := resp.ContentLength
	var written int64
	buf := make([]byte, 256*1024)
	lastReport := time.Now()

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return "", err
			}
			written += int64(n)
			if time.Since(lastReport) > 5*time.Second {
				if totalSize > 0 {
					fmt.Printf("[Maven] Downloaded %.0f MB / %.0f MB (%.0f%%)\n",
						float64(written)/1e6, float64(totalSize)/1e6,
						float64(written)/float64(totalSize)*100)
				}
				lastReport = time.Now()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			f.Close()
			return "", readErr
		}
	}
	f.Close()

	fmt.Printf("[Maven] Download complete: %.0f MB\n", float64(written)/1e6)
	return tmpFile, nil
}

func (c *Client) parseIndex(path string, progress func(count int)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	// Read header: 1 byte version + 8 bytes timestamp
	var version uint8
	var timestamp int64
	binary.Read(gz, binary.BigEndian, &version)
	binary.Read(gz, binary.BigEndian, &timestamp)
	fmt.Printf("[Maven] Index version: %d\n", version)

	var batch []db.DLLMatch
	totalJars := 0
	totalRecords := 0
	startTime := time.Now()

	for {
		var fieldCount int32
		if err := binary.Read(gz, binary.BigEndian, &fieldCount); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return fmt.Errorf("read field count at record %d: %w", totalRecords, err)
		}

		fields := make(map[string]string, fieldCount)
		for i := int32(0); i < fieldCount; i++ {
			var flags uint8
			if err := binary.Read(gz, binary.BigEndian, &flags); err != nil {
				return fmt.Errorf("read flags: %w", err)
			}
			key, err := readString2(gz)
			if err != nil {
				return fmt.Errorf("read key: %w", err)
			}
			val, err := readString4(gz)
			if err != nil {
				return fmt.Errorf("read value for key '%s': %w", key, err)
			}
			fields[key] = val
		}
		totalRecords++

		// Extract artifact info
		u, hasU := fields["u"]
		sha1 := fields["1"]

		if !hasU || sha1 == "" {
			continue
		}

		// u = groupId|artifactId|version|classifier|extension
		// We want records where extension is "jar" (actual JARs, not sha256/asc sidecars)
		parts := strings.Split(u, "|")
		if len(parts) < 3 {
			continue
		}

		groupID := parts[0]
		artifactID := parts[1]
		version := parts[2]

		// Determine the extension from the 'i' field or 'u' field
		// In 'u': parts[3] is classifier (or "NA"), parts[4] is extension
		// We want: no classifier (NA) and extension = jar
		// OR: the 'i' field starts with "jar|"
		isJar := false
		if len(parts) >= 5 {
			classifier := parts[3]
			ext := parts[4]
			isJar = ext == "jar" && (classifier == "NA" || classifier == "")
		} else if len(parts) == 4 {
			// parts[3] could be "NA" for the main artifact
			isJar = parts[3] == "NA"
		}

		// Also check the 'i' field as fallback
		if !isJar {
			if info, ok := fields["i"]; ok {
				if strings.HasPrefix(info, "jar|") {
					// Only if classifier is NA (main artifact, not sources/javadoc)
					if len(parts) >= 4 && (parts[3] == "NA" || parts[3] == "") {
						isJar = true
					}
				}
			}
		}

		if !isJar {
			continue
		}

		jarName := strings.ToLower(artifactID + "-" + version + ".jar")
		packageName := groupID + ":" + artifactID

		batch = append(batch, db.DLLMatch{
			DLLName:     jarName,
			Source:      "maven",
			PackageName: packageName,
			Hash:        strings.ToLower(sha1),
		})
		totalJars++

		if len(batch) >= batchSize {
			if err := c.store.InsertJARBatch(batch); err != nil {
				return fmt.Errorf("insert batch: %w", err)
			}
			batch = batch[:0]

			if progress != nil {
				elapsed := time.Since(startTime)
				rate := float64(totalRecords) / elapsed.Seconds()
				fmt.Printf("[Maven] %d JARs from %d records | %.0f records/s\n",
					totalJars, totalRecords, rate)
			}
		}
	}

	// Flush remaining
	if len(batch) > 0 {
		if err := c.store.InsertJARBatch(batch); err != nil {
			return fmt.Errorf("insert final batch: %w", err)
		}
	}

	elapsed := time.Since(startTime)
	fmt.Printf("[Maven] Done: %d JARs from %d total records in %s\n",
		totalJars, totalRecords, elapsed.Round(time.Second))

	return nil
}

func readString2(r io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readString4(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length > 50_000_000 {
		return "", fmt.Errorf("string too long: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
