package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-github/v71/github"
	"github.com/schollz/progressbar/v3"
)

func TestParseRepoURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rawURL      string
		wantOwner   string
		wantRepo    string
		wantModPath string
		wantErr     bool
	}{
		{
			"Standard GitHub URL",
			"github.com/owner/repo",
			"owner",
			"repo",
			"github.com/owner/repo",
			false,
		},
		{
			"HTTPS URL",
			"https://github.com/owner/repo",
			"owner",
			"repo",
			"github.com/owner/repo",
			false,
		},
		{
			"Trailing Slash",
			"github.com/owner/repo/",
			"owner",
			"repo",
			"github.com/owner/repo",
			false,
		},
		{
			"Git Suffix",
			"github.com/owner/repo.git",
			"owner",
			"repo",
			"github.com/owner/repo",
			false,
		},
		{
			"Subdir (Not handled yet)",
			"github.com/owner/repo/sub",
			"owner",
			"repo",
			"github.com/owner/repo",
			false,
		}, // Current behavior
		{"Too few parts", "github.com/owner", "", "", "", true},
		{"Not GitHub", "gitlab.com/owner/repo", "", "", "", true},
		{"Empty Input", "", "", "", "", true},
		{"Only GitHub", "github.com", "", "", "", true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gotOwner, gotRepo, gotModPath, err := parseRepoURL(testCase.rawURL)
			if (err != nil) != testCase.wantErr {
				t.Errorf("parseRepoURL() error = %v, wantErr %v", err, testCase.wantErr)

				return
			}

			if gotOwner != testCase.wantOwner {
				t.Errorf("parseRepoURL() gotOwner = %v, want %v", gotOwner, testCase.wantOwner)
			}

			if gotRepo != testCase.wantRepo {
				t.Errorf("parseRepoURL() gotRepo = %v, want %v", gotRepo, testCase.wantRepo)
			}

			if gotModPath != testCase.wantModPath {
				t.Errorf(
					"parseRepoURL() gotModPath = %v, want %v",
					gotModPath,
					testCase.wantModPath,
				)
			}
		})
	}
}

func TestDetermineModulePath(t *testing.T) {
	t.Parallel()

	basePath := "github.com/org/repo"
	overrides := map[string]string{
		"1": "gopkg.in/org/repo.v1",
		"3": "github.com/org/repo/v3",
	}

	tests := []struct {
		name     string
		major    string
		wantPath string
		wantSrc  string
	}{
		{"v0 defaults to v1 override", "v0", "gopkg.in/org/repo.v1", "override map"},
		{"v1 uses v1 override", "v1", "gopkg.in/org/repo.v1", "override map"},
		{"v2 uses default path/v2", "v2", "github.com/org/repo/v2", "default (v2)"},
		{"v3 uses v3 override", "v3", "github.com/org/repo/v3", "override map"},
		{"v4 uses default path/v4", "v4", "github.com/org/repo/v4", "default (v4)"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gotPath, gotSrc := determineModulePath(testCase.major, basePath, overrides)
			if gotPath != testCase.wantPath {
				t.Errorf("determineModulePath() gotPath = %v, want %v", gotPath, testCase.wantPath)
			}

			if gotSrc != testCase.wantSrc {
				t.Errorf("determineModulePath() gotSrc = %v, want %v", gotSrc, testCase.wantSrc)
			}
		})
	}
}

func TestIntegration_BasicMatch(t *testing.T) {
	// No t.Parallel() here as it uses httptest.NewServer which might have issues
	// with parallel cleanup or port allocation. Keep integration tests sequential for simplicity.
	// Set up mock GitHub server
	ghMux := http.NewServeMux()
	// Mock Tags endpoint (page 1)
	ghMux.HandleFunc(
		"/api/v3/repos/test-owner/test-repo/tags",
		func(respWriter http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("page") == "2" {
				respWriter.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(respWriter, `[]`) // Check error (ignored)

				return
			}

			respWriter.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(respWriter, `[
			{
				"name": "v1.0.0",
				"commit": {"sha": "abc123match"}
			}
		]`) // Check error (ignored)
		},
	)
	// Mock Commit endpoint
	ghMux.HandleFunc(
		"/api/v3/repos/test-owner/test-repo/git/commits/abc123match",
		func(respWriter http.ResponseWriter, _ *http.Request) {
			respWriter.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(respWriter, `{
			"sha": "abc123match",
			"committer": { "date": "2024-01-01T10:00:00Z" }
		}`) // Check error (ignored)
		},
	)

	githubServer := httptest.NewServer(ghMux)
	defer githubServer.Close()

	// Set up mock Go Proxy server
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc(
		"/github.com/test-owner/test-repo/@v/v1.0.0.info",
		func(respWriter http.ResponseWriter, _ *http.Request) {
			respWriter.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(respWriter, `{
			"Version": "v1.0.0",
			"Time": "2024-01-01T10:05:00Z",
			"Origin": { "Hash": "abc123match" }
		}`) // Check error (ignored)
		},
	)

	proxyServer := httptest.NewServer(proxyMux)
	defer proxyServer.Close()

	ghClient, err := github.NewClient(githubServer.Client()).
		WithEnterpriseURLs(githubServer.URL, githubServer.URL)
	if err != nil {
		t.Fatalf("Failed to create mock GitHub client: %v", err)
	}

	proxyHTTPClient := proxyServer.Client()

	ctx := t.Context()
	eligibleTags := map[string]GitHubTagInfo{
		"v1.0.0": {SHA: "abc123match", Date: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)},
	}
	// No progress bar needed for test
	var bar *progressbar.ProgressBar

	modulePaths := map[string]string{}

	// Using only our mock proxy server - completely predictable and isolated from environment
	proxyList := []string{proxyServer.URL}

	discrepancyCount, checkedCount, procErr := processTags(
		ctx, ghClient, proxyHTTPClient,
		"test-owner", "test-repo", "github.com/test-owner/test-repo",
		modulePaths, proxyList,
		eligibleTags, // Pass the eligible tags map
		bar,          // Pass nil for progress bar
		0,            // limit (0=no limit)
		false,        // verbose
		false,        // failfast
	)

	if procErr != nil {
		t.Errorf("processTags returned unexpected error: %v", procErr)
	}

	if checkedCount != 1 {
		t.Errorf("Expected 1 tag checked, got %d", checkedCount)
	}

	if discrepancyCount != 0 {
		t.Errorf("Expected 0 discrepancies, got %d", discrepancyCount)
	}
}
