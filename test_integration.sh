#!/bin/bash

# test_integration.sh
# Runs the checker against real APIs for basic integration testing.
# Assumes the binary 'checker' exists in the current directory (run make build first).
# Requires GITHUB_TOKEN to be set in the environment for API rate limits.

set -e # Exit on first error

BINARY="./checker"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary $BINARY not found. Run 'make build' first." >&2
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Warning: GITHUB_TOKEN environment variable not set. GitHub API rate limits may apply." >&2
fi

# Save the original GOPROXY value to restore at the end
ORIGINAL_GOPROXY="$GOPROXY"
# Set a predictable GOPROXY for tests
export GOPROXY="https://proxy.golang.org,direct"

echo "--- Running Integration Tests --- "
echo "Using GOPROXY=$GOPROXY for tests (except where explicitly overridden)"

# Test 1: Basic check on cli/cli (expect match, exit 0)
echo "\n>>> Test 1: cli/cli (limit 5, default settings)"
$BINARY -repo github.com/cli/cli -limit 5
if [ $? -ne 0 ]; then
    echo "Test 1 FAILED: Expected exit code 0" >&2
    exit 1
fi
echo "Test 1 PASSED"

# Test 2: Check dd-trace-go with correct module paths (expect match, exit 0)
echo "\n>>> Test 2: Datadog/dd-trace-go (limit 5, verbose, correct paths)"
$BINARY -repo github.com/Datadog/dd-trace-go \
        -module-paths "1=gopkg.in/DataDog/dd-trace-go.v1,2=github.com/DataDog/dd-trace-go/v2" \
        -limit 5 -v
if [ $? -ne 0 ]; then
    echo "Test 2 FAILED: Expected exit code 0" >&2
    exit 1
fi
echo "Test 2 PASSED"

# Test 3: Check cli/cli with pre-release included (expect match, exit 0)
echo "\n>>> Test 3: cli/cli (limit 5, include pre-release)"
$BINARY -repo github.com/cli/cli -limit 5 -include-prerelease
if [ $? -ne 0 ]; then
    echo "Test 3 FAILED: Expected exit code 0" >&2
    exit 1
fi
echo "Test 3 PASSED"

# Test 4: Check cli/cli with date range (expect match, exit 0)
# Adjust dates if needed based on repo history
echo "\n>>> Test 4: cli/cli (limit 5, date range 2024)"
$BINARY -repo github.com/cli/cli -limit 5 -start-date 2024-01-01 -end-date 2024-12-31
if [ $? -ne 0 ]; then
    echo "Test 4 FAILED: Expected exit code 0" >&2
    exit 1
fi
echo "Test 4 PASSED"

# Test 5: Failfast - Currently no reliable public discrepancy to test against.
# echo "\n>>> Test 5: Failfast (Requires known discrepancy - skipping)"

# Test 6: GOPROXY=off (expect exit 0, checks 0 tags)
echo "\n>>> Test 6: GOPROXY=off"
GOPROXY=off $BINARY -repo github.com/cli/cli -limit 5
if [ $? -ne 0 ]; then
    echo "Test 6 FAILED: Expected exit code 0" >&2
    exit 1
fi
# We could potentially check the output log here for "checked 0 tags"
# but for now just check exit code.
echo "Test 6 PASSED"

# Restore the original GOPROXY value
if [ -n "$ORIGINAL_GOPROXY" ]; then
    export GOPROXY="$ORIGINAL_GOPROXY"
else
    unset GOPROXY
fi

echo "\n--- Integration Tests Completed Successfully --- "
exit 0
