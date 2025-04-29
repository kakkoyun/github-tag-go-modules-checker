// Package main implements a tool to check for discrepancies between GitHub tags
// and Go module proxy information for a given repository.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/google/go-github/v71/github"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/mod/semver"
	"golang.org/x/oauth2"
)

// GitHubTagInfo holds the commit SHA and Date for a given tag.
type GitHubTagInfo struct {
	SHA  string
	Date time.Time
}

// ProxyInfo represents the structure of the .info file from the Go proxy.
type ProxyInfo struct {
	Version string      `json:"version"` // The version string (e.g., "v1.2.3")
	Time    time.Time   `json:"time"`    // Timestamp associated with this version by the proxy
	Origin  *OriginInfo `json:"origin"`  // Information about the source commit (optional pointer)
}

// OriginInfo contains details about the source control origin, specifically the commit hash.
type OriginInfo struct {
	Hash string `json:"hash"` // The commit hash (VCS hash) used to build this version.
}

// Constants for configuration defaults and magic numbers.
const (
	defaultTagLimit       = 300
	defaultHTTPTimeoutSec = 30
	keyValueParts         = 2
	defaultGithubPerPage  = 100
	exitCodeUsageError    = 2
	exitCodeGenericError  = 1
	exitCodeSuccess       = 0
	maxLineLength         = 120
)

var (
	repoURLRaw        string
	verbose           bool
	tagLimit          int
	failFast          bool
	includePrerelease bool
	modulePathsRaw    string
	startDateStr      string
	endDateStr        string
)

// Sentinel errors for common issues.
var (
	errFailFastDiscrepancyFound = errors.New("failfast: discrepancy found")
	ErrInvalidGitHubURL         = errors.New(
		"invalid GitHub URL format: expected github.com/owner/repo",
	)
	ErrCouldNotParseOwnerRepo  = errors.New("could not parse owner or repository from URL")
	ErrInvalidProxyEntry       = errors.New("invalid GOPROXY entry")
	ErrProxyVersionNotFound    = errors.New("version not found on proxy")
	ErrUnexpectedProxyStatus   = errors.New("unexpected status from proxy")
	ErrNoSuitableProxyFound    = errors.New("no suitable proxy found or GOPROXY=direct reached")
	ErrInternalProxyLogic      = errors.New("internal logic error during proxy check")
	ErrDiscrepanciesFound      = errors.New("discrepancies found")
	ErrInvalidModulePathFormat = errors.New("invalid format in -module-paths")
	ErrInvalidMajorVersionKey  = errors.New("invalid major version key in -module-paths")
	ErrInvalidStartDate        = errors.New("invalid format for -start-date")
	ErrInvalidEndDate          = errors.New("invalid format for -end-date")
)

// parseRepoURL extracts owner, repository, and potential module path from a GitHub URL.
// It expects formats like "github.com/owner/repo" or "https://github.com/owner/repo".
// For now, assumes module path is the same as the repo path.
func parseRepoURL(rawURL string) (string, string, string, error) {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimSuffix(rawURL, ".git")
	rawURL = strings.TrimSuffix(rawURL, "/")

	parts := strings.Split(rawURL, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return "", "", "", ErrInvalidGitHubURL
	}

	owner := parts[1]
	repo := parts[2]
	modulePath := strings.Join(parts[0:3], "/")

	if owner == "" || repo == "" {
		return "", "", "", ErrCouldNotParseOwnerRepo
	}

	return owner, repo, modulePath, nil
}

// encodeGoModulePath implements the Go module path encoding logic (!c for C).
func encodeGoModulePath(path string) string {
	var buf strings.Builder

	for _, r := range path {
		if unicode.IsUpper(r) {
			buf.WriteByte('!')
			buf.WriteRune(unicode.ToLower(r))
		} else {
			buf.WriteRune(r)
		}
	}

	return buf.String()
}

// determineModulePath selects the correct module path based on the tag's major version
// and the provided overrides map.
func determineModulePath(
	major, derivedModulePath string,
	modulePathsMap map[string]string,
) (string, string) {
	var majorNumStr string
	if len(major) > 1 {
		majorNumStr = major[1:] // e.g., "1", "2", "0"
		if major == "v0" {
			majorNumStr = "1" // Treat v0 as v1 for path lookup
		}
	} else {
		majorNumStr = "1" // Default to v1 logic if major extraction failed
	}

	var (
		actualModulePath string
		pathSource       string
	)

	if pathOverride, ok := modulePathsMap[majorNumStr]; ok {
		actualModulePath = pathOverride
		pathSource = "override map"

		return actualModulePath, pathSource
	}

	if major == "v0" || major == "v1" {
		actualModulePath = derivedModulePath
		pathSource = "default (v0/v1)"
	} else {
		actualModulePath = fmt.Sprintf("%s/%s", derivedModulePath, major)
		pathSource = fmt.Sprintf("default (%s)", major)
	}
	return actualModulePath, pathSource
}

// validateProxyURL validates that the URL is a valid HTTP(S) URL.
// Returns the parsed URL or an error.
func validateProxyURL(proxyURLString string) (*url.URL, error) {
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
		slog.Warn(
			"Skipping invalid or non-HTTP(S) GOPROXY entry",
			slog.String("entry", proxyURLString),
			slog.Any("parse_error", err),
		)

		return nil, fmt.Errorf("%w: %s", ErrInvalidProxyEntry, proxyURLString)
	}

	return proxyURL, nil
}

// handleProxyResponse processes the HTTP response from a proxy.
// Returns the ProxyInfo, a boolean indicating if iteration should stop, and any error encountered.
func handleProxyResponse(
	resp *http.Response,
	bodyBytes []byte,
	readErr error,
	infoURL, proxyURLString string,
) (*ProxyInfo, bool, error) {
	statusCode := resp.StatusCode

	if statusCode == http.StatusOK {
		var proxyInfo ProxyInfo
		if err := json.Unmarshal(bodyBytes, &proxyInfo); err != nil {
			slog.Warn(
				"Failed to decode proxy JSON response",
				slog.String("url", infoURL),
				slog.Any("error", err),
			)

			return nil, false, fmt.Errorf("failed to decode JSON from %s: %w", infoURL, err)
		}

		if proxyInfo.Version == "" || proxyInfo.Time.IsZero() {
			slog.Warn(
				"Received proxy info but Version or Time is missing/zero",
				slog.String("url", infoURL),
				slog.Any("info", proxyInfo),
			)
		}

		slog.Debug("Found version via proxy", slog.String("proxy", proxyURLString))
		return &proxyInfo, true, nil // Success.
	}

	if statusCode == http.StatusNotFound || statusCode == http.StatusGone {
		slog.Debug(
			"Version not found on proxy",
			slog.String("proxy", proxyURLString),
			slog.Int("status", statusCode),
		)

		err := fmt.Errorf(
			"%w %s on proxy %s (%s): %s",
			ErrProxyVersionNotFound,
			strings.Split(infoURL, "/")[len(strings.Split(infoURL, "/"))-1], // Extract version part for error msg
			proxyURLString,
			resp.Status,
			infoURL,
		)

		return nil, false, err // Not found, continue loop
	}

	// Handle unexpected status codes
	var finalErr error
	if readErr != nil {
		finalErr = fmt.Errorf(
			"%w %s from %s and failed to read body: %w",
			ErrUnexpectedProxyStatus,
			resp.Status,
			infoURL,
			readErr,
		)
	} else {
		finalErr = fmt.Errorf("%w %s from %s: %s", ErrUnexpectedProxyStatus, resp.Status, infoURL, string(bodyBytes))
	}

	slog.Warn(
		"Unexpected status from proxy",
		slog.Int("status", statusCode),
		slog.String("url", infoURL),
		slog.Any("error", finalErr),
	)

	return nil, true, finalErr // Found, but error occurred, stop proxy iteration
}

// checkSingleProxy fetches info for a module@version from a specific proxy URL.
// Returns the ProxyInfo, a boolean indicating success, and any error encountered.
func checkSingleProxy(
	ctx context.Context,
	client *http.Client,
	proxyURLString, encodedPath, encodedVersion string,
) (*ProxyInfo, bool, error) {
	proxyURL, err := validateProxyURL(proxyURLString)
	if err != nil {
		return nil, false, err
	}

	baseURL := strings.TrimSuffix(proxyURL.String(), "/")
	infoURL := fmt.Sprintf("%s/%s/@v/%s.info", baseURL, encodedPath, encodedVersion)

	slog.Debug("Attempting proxy lookup", slog.String("url", infoURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		slog.Warn(
			"Failed to create proxy request",
			slog.String("url", infoURL),
			slog.Any("error", err),
		)

		return nil, false, fmt.Errorf("failed to create request for %s: %w", infoURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn(
			"Failed to execute proxy request",
			slog.String("url", infoURL),
			slog.Any("error", err),
		)

		return nil, false, fmt.Errorf("failed to execute request for %s: %w", infoURL, err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn(
				"Failed to close response body",
				slog.String("url", infoURL),
				slog.Any("error", err),
			)
		}
	}()

	bodyBytes, readErr := io.ReadAll(resp.Body)

	return handleProxyResponse(resp, bodyBytes, readErr, infoURL, proxyURLString)
}

// getProxyInfo fetches the .info metadata for a specific module version,
// respecting the GOPROXY list.
func getProxyInfo(
	ctx context.Context,
	client *http.Client,
	modulePath, version string,
	proxyList []string,
) (*ProxyInfo, error) {
	if !strings.HasPrefix(version, "v") {
		slog.Debug(
			"Tag does not start with 'v', proxy lookup might fail",
			slog.String("tag", version),
		)
	}

	encodedPath := encodeGoModulePath(modulePath)

	encodedVersion := encodeGoModulePath(version)

	var lastErr error

	for _, proxy := range proxyList {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		if proxy == "off" {
			msg := "GOPROXY=off, skipping proxy check"
			lastErr = fmt.Errorf(
				"%s for %s@%s: %w",
				msg,
				modulePath,
				version,
				ErrNoSuitableProxyFound,
			)

			slog.Debug(msg, slog.String("module", modulePath), slog.String("version", version))

			return nil, lastErr
		}

		if proxy == "direct" {
			msg := "GOPROXY=direct reached, skipping network lookup"
			lastErr = fmt.Errorf(
				"%s for %s@%s: %w",
				msg,
				modulePath,
				version,
				ErrNoSuitableProxyFound,
			)

			slog.Debug(msg, slog.String("module", modulePath), slog.String("version", version))

			break
		}

		// Extract the logic for checking a single proxy
		proxyInfo, stopIteration, checkErr := checkSingleProxy(
			ctx,
			client,
			proxy,
			encodedPath,
			encodedVersion,
		)

		if checkErr != nil {
			lastErr = checkErr // Record the error
			// If stopIteration is true (e.g., unexpected status), return immediately.
			// If stopIteration is false (e.g., 404), continue to the next proxy.
			if stopIteration {
				return nil, lastErr
			}

			continue
		}

		// If proxyInfo is not nil, we found it successfully
		if proxyInfo != nil {
			slog.Debug(
				"Successfully found version info via proxy",
				slog.String("version", version),
				slog.String("proxy", proxy),
			)

			return proxyInfo, nil
		}

		// If we reach here, checkSingleProxy returned (nil, false, nil), which shouldn't happen.
		// Log a warning and continue, treating it like a non-fatal error for this proxy.
		slog.Warn(
			"Internal logic error: checkSingleProxy returned nil info and nil error without stopIteration",
			slog.String("proxy", proxy),
		)

		lastErr = fmt.Errorf("%w for proxy %s", ErrInternalProxyLogic, proxy) // Use static error
	}

	if lastErr == nil {
		lastErr = fmt.Errorf(
			"%w for %s@%s",
			ErrNoSuitableProxyFound,
			modulePath,
			version,
		)
	}

	return nil, lastErr
}

// validateTagBasics checks if a tag has valid basic properties like name, commit,
// and whether it's a valid semver tag that matches prerelease criteria.
func validateTagBasics(tag *github.RepositoryTag, includePrerelease bool) (string, string, bool) {
	// Check for missing required fields
	if tag.GetName() == "" || tag.GetCommit() == nil || tag.GetCommit().GetSHA() == "" {
		slog.Warn(
			"Skipping tag with missing name or commit SHA during filtering",
			slog.Any("tag_obj", tag),
		)

		return "", "", false
	}

	tagName := tag.GetName()
	commitSHA := tag.GetCommit().GetSHA()

	// Check if it's a valid semver tag
	if !semver.IsValid(tagName) {
		slog.Debug("Filtering out non-semver tag", slog.String("tag", tagName))

		return "", "", false
	}

	// Check if it's a prerelease tag when those are excluded
	isPrerelease := semver.Prerelease(tagName) != ""
	if isPrerelease && !includePrerelease {
		slog.Debug("Filtering out pre-release tag", slog.String("tag", tagName))

		return "", "", false
	}

	// Tag passed all basic validation
	return tagName, commitSHA, true
}

// fetchCommitDate retrieves the commit date for a tag.
// dateFilteringRequired controls whether missing date is considered a failure.
// Returns the commit date and whether the eligibility check should proceed.
func fetchCommitDate(
	ctx context.Context,
	ghClient *github.Client,
	owner, repo, tagName, commitSHA string,
	dateFilteringRequired bool,
) (time.Time, bool) {
	// Early return for non-date-filtering cases where we don't need the date
	// but still want to keep the tag as eligible
	if !dateFilteringRequired {
		// Try to fetch commit info but don't fail eligibility if we can't
		commit, _, commitErr := ghClient.Git.GetCommit(ctx, owner, repo, commitSHA)
		if commitErr != nil {
			slog.Debug(
				"Non-critical: Failed to get commit details for tag info",
				slog.String("tag", tagName),
				slog.String("sha", commitSHA),
				slog.Any("error", commitErr),
			)

			return time.Time{}, true // Allow tag, but with empty date
		}

		if commit.GetCommitter() == nil || commit.GetCommitter().GetDate().IsZero() {
			slog.Debug(
				"Non-critical: Commit missing committer date for tag info",
				slog.String("tag", tagName),
				slog.String("sha", commitSHA),
			)

			return time.Time{}, true // Allow tag, but with empty date
		}

		// Successfully got the date even though we didn't need it for filtering
		return commit.GetCommitter().GetDate().Time, true
	}

	// For date filtering cases, we need the date to proceed
	commit, _, commitErr := ghClient.Git.GetCommit(ctx, owner, repo, commitSHA)
	if commitErr != nil {
		slog.Warn(
			"Failed to get commit details needed for date filtering",
			slog.String("tag", tagName),
			slog.String("sha", commitSHA),
			slog.Any("error", commitErr),
		)

		return time.Time{}, false // Can't filter without date, fail eligibility
	}

	if commit.GetCommitter() == nil || commit.GetCommitter().GetDate().IsZero() {
		slog.Warn(
			"Commit missing committer date needed for filtering",
			slog.String("tag", tagName),
			slog.String("sha", commitSHA),
		)

		return time.Time{}, false // Can't filter without date, fail eligibility
	}

	// Success - return the date
	return commit.GetCommitter().GetDate().Time, true
}

// isDateInRange checks if the commit date is within the specified date range.
func isDateInRange(
	tagName string,
	commitDate time.Time,
	startDate, endDate time.Time,
) bool {
	// Check if the commit date is before the start date
	if !startDate.IsZero() && commitDate.Before(startDate) {
		slog.Debug(
			"Filtering out tag before start date",
			slog.String("tag", tagName),
			slog.Time("commit_date", commitDate),
			slog.Time("start_date", startDate),
		)

		return false
	}

	// Check if the commit date is after the end date
	if !endDate.IsZero() && commitDate.After(endDate) {
		slog.Debug(
			"Filtering out tag after end date",
			slog.String("tag", tagName),
			slog.Time("commit_date", commitDate),
			slog.Time("end_date", endDate),
		)

		return false
	}

	// Date is within range
	return true
}

// isTagEligible checks if a single GitHub tag meets the filtering criteria.
func isTagEligible(
	ctx context.Context,
	ghClient *github.Client,
	owner, repo string,
	tag *github.RepositoryTag,
	startDate, endDate time.Time,
	includePrerelease bool,
) (*GitHubTagInfo, bool) {
	// Check basic tag validity (name, semver, prerelease)
	tagName, commitSHA, valid := validateTagBasics(tag, includePrerelease)
	if !valid {
		return nil, false
	}

	// Determine if we need date filtering
	dateFilteringRequired := !startDate.IsZero() || !endDate.IsZero()

	// Get the commit date if possible
	commitDate, shouldProceed := fetchCommitDate(
		ctx,
		ghClient,
		owner,
		repo,
		tagName,
		commitSHA,
		dateFilteringRequired,
	)

	// Early return if commit date retrieval failed (only when needed for filtering)
	if !shouldProceed {
		return nil, false
	}

	// Apply date filtering if needed and we have a date
	if dateFilteringRequired && !commitDate.IsZero() {
		if !isDateInRange(tagName, commitDate, startDate, endDate) {
			return nil, false
		}
	}

	// Tag passes all criteria
	return &GitHubTagInfo{SHA: commitSHA, Date: commitDate}, true
}

// getEligibleGitHubTags fetches all tags from GitHub and filters them based on criteria.
func getEligibleGitHubTags(
	ctx context.Context,
	ghClient *github.Client,
	owner, repo string,
	startDate, endDate time.Time,
	includePrerelease bool,
	limit int,
) (map[string]GitHubTagInfo, error) {
	eligibleTags := make(map[string]GitHubTagInfo)
	opts := &github.ListOptions{PerPage: defaultGithubPerPage, Page: 0}

	slog.Info("Fetching all GitHub tags to determine eligibility...")

	pageCount := 0
	githubTagsSeen := 0

	for {
		pageCount++
		slog.Debug("Fetching GitHub tags page for filtering", slog.Int("page", pageCount))

		tags, resp, ghErr := ghClient.Repositories.ListTags(ctx, owner, repo, opts)
		if ghErr != nil {
			// Check for RateLimitError specifically
			rateLimitErr := &github.RateLimitError{
				Rate:     github.Rate{},
				Response: nil,
				Message:  "",
			}
			if errors.As(ghErr, &rateLimitErr) {
				// If it IS a RateLimitError, errors.As populates rateLimitErr.
				// We only need to log the reset time, which should be populated.
				slog.Warn(
					"Hit GitHub rate limit during tag filtering",
					slog.Time("reset", rateLimitErr.Rate.Reset.Time), // Access nested Time
				)
			}

			return nil, fmt.Errorf(
				"failed to list tags for filtering (page %d): %w",
				pageCount,
				ghErr,
			)
		}

		if len(tags) == 0 {
			break
		}

		slog.Debug(
			"Filtering GitHub tags from page",
			slog.Int("page", pageCount),
			slog.Int("count", len(tags)),
		)

		for _, tag := range tags {
			githubTagsSeen++
			// Use helper function to check eligibility
			ghInfo, eligible := isTagEligible(
				ctx, ghClient, owner, repo, tag,
				startDate, endDate, includePrerelease,
			)
			if eligible {
				eligibleTags[tag.GetName()] = *ghInfo
				// Break long line
				slog.Debug("Added eligible tag",
					slog.String("tag", tag.GetName()),
					slog.String("sha", ghInfo.SHA),
				)

				// Stop when we reach the limit
				if limit > 0 && len(eligibleTags) >= limit {
					slog.Info("Reached tag limit during filtering",
						slog.Int("limit", limit),
						slog.Int("eligible_tags", len(eligibleTags)),
						slog.Int("total_tags_seen", githubTagsSeen),
					)
					// Return early since we have enough tags
					return eligibleTags, nil
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	slog.Info(
		"Finished filtering GitHub tags",
		slog.Int("total_tags_seen", githubTagsSeen),
		slog.Int("eligible_tags", len(eligibleTags)),
	)

	return eligibleTags, nil
}

// determineTagModulePath gets the module path for a tag version based on its major version.
func determineTagModulePath(
	tagName, derivedModulePath string,
	modulePathsMap map[string]string,
) (string, string) {
	major := semver.Major(tagName)
	actualModulePath, pathSource := determineModulePath(
		major,
		derivedModulePath,
		modulePathsMap,
	)

	slog.Debug(
		"Determined module path for check",
		slog.String("tag", tagName),
		slog.String("major", major),
		slog.String("module_path", actualModulePath),
		slog.String("source", pathSource),
	)

	return actualModulePath, major
}

// formatDates formats the GitHub and proxy dates for logging.
func formatDates(githubInfo GitHubTagInfo, proxyInfo *ProxyInfo) (string, string) {
	githubDateStr := "(no date)"
	if !githubInfo.Date.IsZero() {
		githubDateStr = githubInfo.Date.Format(time.RFC3339)
	}

	proxyTimeStr := "(no time)"
	if proxyInfo != nil && !proxyInfo.Time.IsZero() {
		proxyTimeStr = proxyInfo.Time.Format(time.RFC3339)
	}

	return githubDateStr, proxyTimeStr
}

// compareCommitHashes checks if there's a discrepancy between GitHub and proxy commit hashes.
// Returns true if a discrepancy is found, and the proxyCommitHash.
func compareCommitHashes(
	tagName string,
	githubInfo GitHubTagInfo,
	proxyInfo *ProxyInfo,
) (bool, string) {
	var proxyCommitHash string
	if proxyInfo.Origin != nil {
		proxyCommitHash = proxyInfo.Origin.Hash
	}

	match := githubInfo.SHA == proxyCommitHash

	githubDateStr, proxyTimeStr := formatDates(githubInfo, proxyInfo)

	if match {
		slog.Debug("Tag versions match",
			slog.String("tag", tagName),
			slog.String("github_commit", githubInfo.SHA),
			slog.String("github_date", githubDateStr),
			slog.String("proxy_commit", proxyCommitHash),
			slog.String("proxy_time", proxyTimeStr),
		)

		return false, proxyCommitHash
	}

	// Discrepancy found.
	slog.Warn("Discrepancy found",
		slog.String("tag", tagName),
		slog.String("github_commit", githubInfo.SHA),
		slog.String("proxy_commit", proxyCommitHash),
		slog.String("github_date", githubDateStr),
		slog.String("proxy_time", proxyTimeStr),
	)

	return true, proxyCommitHash
}

// checkSingleTag compares GitHub tag info against Go proxy info for a single tag.
// Returns true if a discrepancy is found, the proxy info (if found), and any error during proxy lookup.
func checkSingleTag(
	ctx context.Context,
	ghClient *github.Client,
	proxyClient *http.Client,
	owner, repo, derivedModulePath, tagName string,
	githubInfo GitHubTagInfo,
	modulePathsMap map[string]string,
	proxyList []string,
	verbose bool,
) (bool, string, error) {
	actualModulePath, _ := determineTagModulePath(tagName, derivedModulePath, modulePathsMap)

	if verbose {
		logVerboseCommitDetails(ctx, ghClient, owner, repo, tagName, githubInfo)
	}

	proxyInfo, proxyErr := getProxyInfo(ctx, proxyClient, actualModulePath, tagName, proxyList)
	if proxyErr != nil {
		errMsg := proxyErr.Error()
		if errors.Is(proxyErr, ErrProxyVersionNotFound) ||
			strings.Contains(errMsg, "GOPROXY=off") ||
			strings.Contains(errMsg, "GOPROXY=direct") ||
			errors.Is(proxyErr, ErrNoSuitableProxyFound) {
			slog.Debug(
				"Tag not processed via proxy",
				slog.String("tag", tagName),
				slog.String("reason", errMsg),
			)
		} else {
			slog.Warn("Failed to get proxy info", slog.String("tag", tagName), slog.Any("error", proxyErr))
		}

		return false, "", proxyErr // Return error, no discrepancy check possible
	}

	// Compare GitHub SHA with proxy commit hash
	discrepancyFound, proxyCommitHash := compareCommitHashes(tagName, githubInfo, proxyInfo)

	return discrepancyFound, proxyCommitHash, nil
}

// processTags iterates through eligible tags and checks for discrepancies using checkSingleTag.
func processTags(
	ctx context.Context,
	ghClient *github.Client,
	proxyClient *http.Client,
	owner, repo, derivedModulePath string,
	modulePathsMap map[string]string,
	proxyList []string,
	eligibleTags map[string]GitHubTagInfo,
	bar *progressbar.ProgressBar,
	limit int,
	verbose, failFast bool,
) (int, int, error) {
	slog.Debug(
		"Starting tag processing phase",
		slog.Int("eligible_count", len(eligibleTags)),
		slog.Int("limit", limit),
		slog.Bool("failfast", failFast),
	)

	var discrepancyCount, checkedCount int

	processedLimitCounter := 0

	// Determine the maximum number of items to process for progress tracking
	maxToProcess := len(eligibleTags)
	if limit > 0 && limit < maxToProcess {
		maxToProcess = limit
	}

	for tagName, githubInfo := range eligibleTags {
		if limit > 0 && processedLimitCounter >= limit {
			slog.Info(
				"Reached tag check limit for eligible tags",
				slog.Int("limit", limit),
				slog.Int("checked_so_far", processedLimitCounter),
			)

			break
		}

		processedLimitCounter++

		// Call helper to check the single tag
		discrepancy, _, proxyErr := checkSingleTag(
			ctx,
			ghClient,
			proxyClient,
			owner, repo, derivedModulePath,
			tagName,
			githubInfo,
			modulePathsMap,
			proxyList,
			verbose,
		)

		// Increment progress bar regardless of proxy error for this tag, unless failfast triggers exit
		if bar != nil {
			_ = bar.Add(1)
		}

		if proxyErr == nil { // Only count as checked if proxy lookup was successful
			checkedCount++
		}

		if discrepancy {
			discrepancyCount++

			if failFast {
				slog.Warn("Exiting due to failfast flag", slog.String("tag", tagName))

				return discrepancyCount, checkedCount, errFailFastDiscrepancyFound
			}
		}
	}

	slog.Info("Finished processing eligible tags")

	return discrepancyCount, checkedCount, nil
}

// logVerboseCommitDetails fetches and logs author/committer date differences if verbose is enabled.
func logVerboseCommitDetails(
	ctx context.Context,
	ghClient *github.Client,
	owner, repo, tagName string,
	githubInfo GitHubTagInfo,
) {
	commit, _, commitErr := ghClient.Git.GetCommit(ctx, owner, repo, githubInfo.SHA)
	if commitErr == nil {
		if author := commit.GetAuthor(); author != nil && !author.GetDate().IsZero() {
			authorDate := author.GetDate().Time
			if !githubInfo.Date.IsZero() && !authorDate.Equal(githubInfo.Date) {
				slog.Debug(
					"Commit Author/Committer dates differ",
					slog.String("tag", tagName),
					slog.String("sha", githubInfo.SHA),
					slog.Time("author_date", authorDate),
					slog.Time("committer_date", githubInfo.Date),
					slog.Duration("difference", githubInfo.Date.Sub(authorDate)),
				)
			}
		} // No need to log warnings here again if author/committer missing
	} else {
		slog.Warn(
			"Failed to re-fetch commit details for verbose check",
			slog.String("tag", tagName),
			slog.String("sha", githubInfo.SHA),
			slog.Any("error", commitErr),
		)
	}
}

// setupGitHubClient creates and configures a GitHub client with authentication if available.
func setupGitHubClient(ctx context.Context) *github.Client {
	var ghHTTPClient *http.Client

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken != "" {
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken:  githubToken,
			TokenType:    "",
			RefreshToken: "",
			Expiry:       time.Time{},
			ExpiresIn:    0,
		})

		ghHTTPClient = oauth2.NewClient(ctx, tokenSource)

		slog.Info("Using GITHUB_TOKEN for GitHub authentication")
	} else {
		slog.Warn("GITHUB_TOKEN not found. Making unauthenticated requests to GitHub API (rate limits may apply).")

		ghHTTPClient = nil
	}

	return github.NewClient(ghHTTPClient)
}

// setupProgressBar initializes a progress bar for tracking tag processing.
func setupProgressBar(totalTags int, limit int, verbose bool) *progressbar.ProgressBar {
	if verbose {
		return nil
	}

	// Determine the number of operations to track
	operationCount := totalTags
	description := "Checking tags..."

	// If there's a limit and it's smaller than the total tags, use it for the progress bar
	if limit > 0 && limit < totalTags {
		operationCount = limit
		description = fmt.Sprintf("Checking tags (limited to %d)...", limit)
		slog.Debug(
			"Progress bar limited",
			slog.Int("total_eligible", totalTags),
			slog.Int("limit", limit),
		)
	}

	return progressbar.NewOptions(operationCount,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr), // Write to stderr
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:         "=",
			SaucerHead:     ">",
			SaucerPadding:  " ",
			BarStart:       "[",
			BarEnd:         "]",
			AltSaucerHead:  ">",
			BarStartFilled: "[",
			BarEndFilled:   "]",
		}))
}

// checkTagDiscrepancies processes all eligible tags and reports any discrepancies.
func checkTagDiscrepancies(
	ctx context.Context,
	githubClient *github.Client,
	proxyClient *http.Client,
	owner, repo, derivedModulePath string,
	modulePathsMap map[string]string,
	proxyList []string,
	eligibleTags map[string]GitHubTagInfo,
	bar *progressbar.ProgressBar,
	tagLimit int,
	verbose, failFast bool,
) error {
	discrepancyCount, checkedCount, err := processTags(
		ctx, githubClient, proxyClient, owner, repo, derivedModulePath,
		modulePathsMap, proxyList, eligibleTags, bar, tagLimit, verbose, failFast,
	)

	if bar != nil {
		_ = bar.Finish() // Mark bar as done

		fmt.Fprintln(os.Stderr) // Add a newline after the bar finishes
	}

	if err != nil {
		if errors.Is(err, errFailFastDiscrepancyFound) {
			return err // Return specific error for exit code handling
		}

		slog.Error("Error processing tags", slog.Any("error", err))

		return err
	}

	// Final Summary
	slog.Info("Check complete",
		slog.Int("tags_checked_on_proxy", checkedCount),
		slog.Int("discrepancies_found", discrepancyCount),
	)

	if discrepancyCount > 0 {
		slog.Error("Exiting with non-zero status due to discrepancies found.")

		return fmt.Errorf(
			"%w: %d found",
			ErrDiscrepanciesFound,
			discrepancyCount,
		) // Use static error
	}

	slog.Info("No discrepancies found.")

	return nil // Success
}

// runApp encapsulates the main application logic after flag parsing.
func runApp() error {
	owner, repo, derivedModulePath, err := parseRepoURL(repoURLRaw)
	if err != nil {
		slog.Error(
			"Failed parsing repository URL",
			slog.String("url", repoURLRaw),
			slog.Any("error", err),
		)

		return err
	}

	// Log configuration
	slog.Info("Configuration loaded",
		slog.String("repository", owner+"/"+repo),
		slog.String("base_module_path", derivedModulePath),
		slog.Bool("verbose", verbose),
		slog.Int("limit", tagLimit),
		slog.Bool("failfast", failFast),
		slog.Bool("include_prerelease", includePrerelease),
	)

	// Parse GOPROXY
	goProxy := os.Getenv("GOPROXY")
	if goProxy == "" {
		goProxy = "https://proxy.golang.org,direct" // Default behavior of go command
	}

	proxyList := strings.Split(goProxy, ",")
	slog.Info("Using GOPROXY setting", slog.String("value", goProxy), slog.Any("parsed", proxyList))

	ctx := context.Background()
	githubClient := setupGitHubClient(ctx)

	// Initialize HTTP client for Go Proxy
	proxyClient := &http.Client{
		Timeout:       defaultHTTPTimeoutSec * time.Second,
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
	}

	// Parse module path overrides
	modulePathsMap, err := parseModulePaths(modulePathsRaw)
	if err != nil {
		return err
	}

	// Parse date filters
	startDate, endDate, err := parseDateFilters(startDateStr, endDateStr)
	if err != nil {
		return err
	}

	// Get eligible tags first
	eligibleTags, err := getEligibleGitHubTags(
		ctx,
		githubClient,
		owner,
		repo,
		startDate,
		endDate,
		includePrerelease,
		tagLimit,
	)
	if err != nil {
		slog.Error("Error getting eligible GitHub tags", slog.Any("error", err))

		return err
	}

	if len(eligibleTags) == 0 {
		slog.Info("No eligible tags found matching the criteria.")

		return nil // Successful exit
	}

	// Initialize progress bar
	bar := setupProgressBar(len(eligibleTags), tagLimit, verbose)

	// Process tags and check for discrepancies
	return checkTagDiscrepancies(
		ctx, githubClient, proxyClient, owner, repo, derivedModulePath,
		modulePathsMap, proxyList, eligibleTags, bar, tagLimit, verbose, failFast,
	)
}

// parseModulePaths parses the -module-paths flag value.
func parseModulePaths(rawPaths string) (map[string]string, error) {
	modulePathsMap := make(map[string]string)
	if rawPaths == "" {
		return modulePathsMap, nil
	}

	pairs := strings.Split(rawPaths, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", keyValueParts)
		if len(parts) != keyValueParts || parts[0] == "" || parts[1] == "" {
			errMsg := "pair: " + pair
			slog.Error(ErrInvalidModulePathFormat.Error(), slog.String("details", errMsg))

			return nil, fmt.Errorf("%w: %s", ErrInvalidModulePathFormat, errMsg)
		}

		majorVerKey := strings.TrimSpace(parts[0])
		modulePathVal := strings.TrimSpace(parts[1])

		if _, err := fmt.Sscan(majorVerKey, new(int)); err != nil {
			errMsg := "key: " + majorVerKey
			slog.Error(
				ErrInvalidMajorVersionKey.Error(),
				slog.String("details", errMsg),
				slog.Any("scan_error", err),
			)

			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidMajorVersionKey, errMsg, err)
		}

		modulePathsMap[majorVerKey] = modulePathVal
	}

	slog.Debug("Parsed module paths map", slog.Any("map", modulePathsMap))

	return modulePathsMap, nil
}

// parseDateFilters parses the -start-date and -end-date flag values.
func parseDateFilters(startStr, endStr string) (time.Time, time.Time, error) {
	var startDate, endDate time.Time

	var err error

	if startStr != "" {
		startDate, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			errMsg := "value: " + startStr
			slog.Error(
				ErrInvalidStartDate.Error(),
				slog.String("details", errMsg),
				slog.Any("parse_error", err),
			)

			return time.Time{}, time.Time{}, fmt.Errorf(
				"%w: %s: %w",
				ErrInvalidStartDate,
				errMsg,
				err,
			)
		}

		startDate = time.Date(
			startDate.Year(),
			startDate.Month(),
			startDate.Day(),
			0,
			0,
			0,
			0,
			startDate.Location(),
		)
		slog.Info("Using start date filter", slog.Time("date", startDate))
	}

	if endStr != "" {
		endDate, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			errMsg := "value: " + endStr
			slog.Error(
				ErrInvalidEndDate.Error(),
				slog.String("details", errMsg),
				slog.Any("parse_error", err),
			)

			return time.Time{}, time.Time{}, fmt.Errorf(
				"%w: %s: %w",
				ErrInvalidEndDate,
				errMsg,
				err,
			)
		}

		endDate = time.Date(
			endDate.Year(),
			endDate.Month(),
			endDate.Day(),
			23,
			59,
			59,
			999999999,
			endDate.Location(),
		)
		slog.Info("Using end date filter", slog.Time("date", endDate))
	}

	return startDate, endDate, nil
}

func main() {
	flag.StringVar(
		&repoURLRaw,
		"repo",
		"",
		"GitHub repository URL (e.g., github.com/owner/repo) (required)",
	)
	flag.BoolVar(&verbose, "v", false, "Enable verbose output (shows all tags checked)")
	flag.IntVar(
		&tagLimit,
		"limit",
		defaultTagLimit,
		"Maximum number of recent tags to check (0 for no limit)",
	)
	flag.BoolVar(
		&failFast,
		"failfast",
		false,
		"Exit immediately after finding the first discrepancy",
	)
	flag.BoolVar(
		&includePrerelease,
		"include-prerelease",
		false,
		"Include pre-release versions (e.g., -rc, -beta) in checks",
	)
	flag.StringVar(
		&modulePathsRaw,
		"module-paths",
		"",
		"Comma-separated key=value pairs for module paths per major version (e.g., '1=path/v1,2=path/v2')",
	)
	flag.StringVar(
		&startDateStr,
		"start-date",
		"",
		"Only check tags created on or after this date (YYYY-MM-DD)",
	) // Added
	flag.StringVar(
		&endDateStr,
		"end-date",
		"",
		"Only check tags created on or before this date (YYYY-MM-DD)",
	) // Added

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -repo <URL> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Checks GitHub tags against Go module proxy data.\n\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse() // Parse flags

	// Setup logger (must happen after flag parsing for -v)
	logLevel := new(slog.LevelVar) // Default to Info
	if verbose {
		logLevel.Set(slog.LevelDebug)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:       logLevel,
		AddSource:   false,
		ReplaceAttr: nil,
	}))
	slog.SetDefault(logger)

	// Validate required flags
	if repoURLRaw == "" {
		slog.Error("-repo flag is required")
		flag.Usage()
		os.Exit(exitCodeUsageError) // Use constant
	}

	// Run the main application logic
	if err := runApp(); err != nil {
		// Specific exit code for failfast
		if errors.Is(err, errFailFastDiscrepancyFound) {
			os.Exit(exitCodeGenericError)
		}
		// Generic error exit code
		slog.Error("Application run failed", slog.Any("error", err))
		os.Exit(exitCodeGenericError)
	}
	// Success exit code is 0 (default)
}
