# hyoketsu

Offline identification of DLLs and JARs by filename and hash. Built for research/RE projects where you need to quickly separate known standard libraries from custom code.

Database sources:
- **Maven Central** 
- **NuGet** 

## Build

Requires Go 1.22+.

```
go build -o hyoketsu .
```

## Build the database

This is the slow part. Run on a server with good bandwidth.

```
# Full update (Maven + NuGet in parallel)
./hyoketsu update

# Maven only (~30 min, downloads 2.6GB index)
./hyoketsu update --skip-nuget

# NuGet only (~12h for catalog crawl + hash backfill)
./hyoketsu update --skip-maven

# More workers (default 128)
./hyoketsu update --workers 256
```

The database is stored at `~/.hyoketsu/hyoketsu.db`. Both crawls support resuming — if interrupted, re-run the same command to continue from where it stopped.

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
