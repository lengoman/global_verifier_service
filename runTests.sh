#!/bin/bash

# Print header
echo "Running all tests..."
echo "==================="

# Function to run tests and check for errors
run_tests() {
    local name=$1
    local command=$2
    
    echo "Running tests for $name..."
    if $command; then
        echo "✅ $name tests passed"
    else
        echo "❌ $name tests failed"
        exit 1
    fi
    echo "-------------------"
}

# Run tests for all binaries
run_tests "verifier" "cargo test --bin verifier -- --nocapture --test-threads=1"
run_tests "holder" "cargo test --bin holder -- --nocapture --test-threads=1"

# Run tests for library
run_tests "library" "cargo test --lib -- --nocapture --test-threads=1"

# Print summary
echo "==================="
echo "All tests completed successfully!" 