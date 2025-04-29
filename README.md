# GitHub Tag vs Go Proxy Checker

Checks for discrepancies between GitHub tags/commits and Go module proxy data for a given repository. Useful for identifying potential inconsistencies or mismatches in published module versions.

## Usage

```bash
# Build
go build -o checker

# Run
./checker -repo <github.com/owner/repo> [-v] [-limit 50]
```

Alternatively, run directly:

```bash
go run main.go -repo <github.com/owner/repo> [-v] [-limit 50]
```

## Flags

* `-repo string`: (Required) GitHub repository URL (e.g., `github.com/spf13/cobra` or `https://github.com/spf13/cobra`).
* `-v bool`: (Optional) Enable verbose output. Shows details for all tags checked (including timestamps and commit match status), not just discrepancies. Defaults to `false`.
* `-limit int`: (Optional) Maximum number of recent tags to check. The tool will stop fetching tags from GitHub once this limit is reached, improving performance for repositories with many tags. Default is `300`. Use `0` for no limit.
* `-failfast bool`: (Optional) Exit immediately after finding the first discrepancy. Default is `false`.
* `-include-prerelease bool`: (Optional) Include pre-release versions (e.g., -rc, -beta) in checks. Default is `false`.
* `-module-paths string`: (Optional) Comma-separated key=value pairs for module paths per major version (e.g., '1=path/v1,2=path/v2').
* `-start-date string`: (Optional) Only check tags created on or after this date (YYYY-MM-DD).
* `-end-date string`: (Optional) Only check tags created on or before this date (YYYY-MM-DD).

## Authentication

The tool reads the `GITHUB_TOKEN` environment variable to authenticate with the GitHub API. This is recommended for private repositories or to avoid hitting rate limits on public repositories.

```bash
export GITHUB_TOKEN="your_personal_access_token"
./checker -repo <github.com/owner/private-repo>
```

## Example Output

**Standard (only shows discrepancies and summary):**

```
time=2025-04-29T13:09:59.837+02:00 level=WARN msg="Discrepancy found" tag=v1.2.0 github_commit=abc123def proxy_commit=xyz789abc github_date=2023-02-15T12:00:00Z proxy_time=2023-02-15T12:10:00Z
time=2025-04-29T13:09:59.837+02:00 level=INFO msg="Check complete" tags_checked_on_proxy=30 discrepancies_found=1
time=2025-04-29T13:09:59.837+02:00 level=ERROR msg="Exiting with non-zero status due to discrepancies found."
```

**Verbose (shows all tags checked and detailed processing):**

```
time=2025-04-29T13:09:58.586+02:00 level=DEBUG msg="Starting tag processing phase" eligible_count=3 limit=3 failfast=false
time=2025-04-29T13:09:58.586+02:00 level=DEBUG msg="Determined module path for check" tag=v2.71.2 major=v2 module_path=github.com/cli/cli/v2 source="default (v2)"
time=2025-04-29T13:09:59.078+02:00 level=DEBUG msg="Found version via proxy" proxy=https://proxy.golang.org
time=2025-04-29T13:09:59.078+02:00 level=DEBUG msg="Successfully found version info via proxy" version=v2.71.2 proxy=https://proxy.golang.org
time=2025-04-29T13:09:59.078+02:00 level=DEBUG msg="Tag versions match" tag=v2.71.2 github_commit=fb97b3ef... github_date=2025-04-24T16:41:14Z proxy_commit=fb97b3ef... proxy_time=2025-04-24T16:41:14Z
time=2025-04-29T13:09:59.837+02:00 level=INFO msg="Check complete" tags_checked_on_proxy=3 discrepancies_found=0
time=2025-04-29T13:09:59.837+02:00 level=INFO msg="No discrepancies found."
```

**With detected discrepancies in verbose mode:**

```
time=2025-04-29T13:09:59.078+02:00 level=DEBUG msg="Tag versions match" tag=v2.71.2 github_commit=fb97b3ef... github_date=2025-04-24T16:41:14Z proxy_commit=fb97b3ef... proxy_time=2025-04-24T16:41:14Z
time=2025-04-29T13:09:59.472+02:00 level=WARN msg="Discrepancy found" tag=v2.71.1 github_commit=c378b18a... github_date=2025-04-24T13:27:27Z proxy_commit=def456... proxy_time=2025-04-24T13:27:27Z
time=2025-04-29T13:09:59.837+02:00 level=INFO msg="Check complete" tags_checked_on_proxy=3 discrepancies_found=1
time=2025-04-29T13:09:59.837+02:00 level=ERROR msg="Exiting with non-zero status due to discrepancies found."
```

## Performance Optimization

The tool optimizes GitHub API usage by stopping tag fetching once the specified limit is reached. This is particularly useful for repositories with many tags when you only need to check the most recent ones.

For example, using `-limit 50` will fetch only enough tags to find 50 eligible ones, saving API calls and processing time.
