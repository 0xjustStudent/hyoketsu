# hyoketsu

Offline identification of DLLs and JARs by filename and hash. Built for research/RE projects where you need to quickly separate known standard libraries from custom code.

Database sources:
- **Maven Central** — JARs matched by SHA1 hash and filename
- **NuGet** — DLLs matched by SHA256 hash and filename

## Build

Requires Go 1.22+.

```
go build -o hyoketsu .
```

## Database setup

The database is stored at `~/.hyoketsu/hyoketsu.db`.

### Option A: Download pre-built database (recommended)

If no local database exists, `hyoketsu scan` will offer to download a pre-built database from the Assetnote team. Just run a scan and answer `y` when prompted:

```
./hyoketsu scan /path/to/project
# No local database found at ~/.hyoketsu/hyoketsu.db
# A pre-built database from the Assetnote team is available (built February 20, 2026).
# Would you like to download it? [y/N]: y
```

You can also manually download it:

```
mkdir -p ~/.hyoketsu
curl -o ~/.hyoketsu/hyoketsu.db https://wordlists-cdn.assetnote.io/hyoketsu/hyoketsu.db
```

### Option B: Build the database from scratch

This is the slow path. Run on a server with good bandwidth.

**Step 1: Crawl package registries**

```
# Full crawl (Maven + NuGet in parallel)
./hyoketsu update

# Maven only (~30 min, downloads 2.6GB Lucene index)
# Inserts JARs with SHA1 hashes directly into the DB.
./hyoketsu update --skip-nuget

# NuGet only (catalog crawl, writes JSONL to data/nuget/crawl/)
# NOTE: This does NOT insert into the DB — see steps 2 and 3.
./hyoketsu update --skip-maven

# More workers (default 128)
./hyoketsu update --workers 256
```

Maven data is inserted directly into the database during this step. NuGet data is written as JSONL files only.

**Step 2: Backfill NuGet DLL hashes (optional but recommended)**

Downloads each .nupkg, extracts DLLs, and computes SHA256 hashes. Without this, NuGet matching is filename-only (no hash matching).

```
./hyoketsu hash-backfill

# More workers
./hyoketsu hash-backfill --workers 256
```

Reads from `data/nuget/crawl/`, writes hashed entries to `data/nuget/hashes/`. Supports resuming — already-hashed packages are skipped on re-run.

**Step 3: Import NuGet data into the database**

```
./hyoketsu import
```

Reads JSONL from both `data/nuget/crawl/` and `data/nuget/hashes/`, merges them (preferring hashed versions), and bulk-inserts into the `known_dlls` table.

**Full NuGet pipeline summary:**

```
./hyoketsu update --skip-maven    # Step 1: crawl catalog → JSONL files
./hyoketsu hash-backfill          # Step 2: download nupkgs → hashed JSONL files
./hyoketsu import                 # Step 3: merge JSONL → SQLite
```

Once built, copy the `.db` file to any machine where you need to scan.

## Scan

```
# Scan a directory
./hyoketsu scan /path/to/project

# JSON output
./hyoketsu scan --json /path/to/project

# Show only unknown files
./hyoketsu scan --unknown-only /path/to/project

# Only .NET assemblies
./hyoketsu scan --dotnet-only /path/to/project

# Hide duplicates
./hyoketsu scan --dedup /path/to/project

# Show only hash-matched files
./hyoketsu scan --hash /path/to/project

# Show only filename-matched files
./hyoketsu scan --filename /path/to/project

# Scan against a remote hyoketsu server instead of local DB
./hyoketsu scan --remote http://host:8080 /path/to/project
```

Matching order: hash first, then filename fallback (catches renamed files).

## Extract unknowns

Copy unidentified files to a separate directory for further analysis.

```
./hyoketsu extract /path/to/project /path/to/output

# Flatten into single directory
./hyoketsu extract --flat /path/to/project /path/to/output

# Only .NET, skip dupes
./hyoketsu extract --dotnet-only --dedup /path/to/project /path/to/output
```

## Stats

```
./hyoketsu stats
```
