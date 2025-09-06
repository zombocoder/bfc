# BFC Project Makefile
# Copyright 2021 zombocoder (Taras Havryliak)
# Licensed under the Apache License, Version 2.0

# Build configuration
BUILD_DIR := build
CMAKE_BUILD_TYPE ?= Debug

# Source directories
SRC_DIRS := src include tests examples
SOURCE_FILES := $(shell find $(SRC_DIRS) -name "*.c" -o -name "*.h" 2>/dev/null)

# Coverage configuration
COVERAGE_DIR := $(BUILD_DIR)/coverage
COVERAGE_INFO := $(COVERAGE_DIR)/coverage.info
COVERAGE_HTML := $(COVERAGE_DIR)/html
COVERAGE_THRESHOLD := 90

.PHONY: all clean configure build test format format-check format-fix coverage coverage-report cppcheck help

# Default target
all: build test

# Help target
help:
	@echo "BFC Project Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build           - Build the project"
	@echo "  test            - Run all tests"
	@echo "  format-check    - Check code formatting (dry-run)"
	@echo "  format-fix      - Fix code formatting"
	@echo "  coverage        - Run coverage tests with lcov"
	@echo "  coverage-report - Generate HTML coverage report"
	@echo "  cppcheck        - Run static analysis with cppcheck"
	@echo "  clean           - Clean build artifacts"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  CMAKE_BUILD_TYPE - Build type (Debug, Release) [default: Debug]"

# Configure CMake
configure:
	@echo "Configuring CMake build..."
	cmake -B $(BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
		-DBFC_WITH_ZSTD=ON
		-DBFC_WITH_SODIUM=ON

# Build the project
build: configure
	@echo "Building project..."
	cmake --build $(BUILD_DIR)

# Run tests
test: build
	@echo "Running tests..."
	ctest --test-dir $(BUILD_DIR) --output-on-failure

# Check code formatting (dry-run)
format-check:
	@echo "Checking code formatting..."
	@if [ -z "$(SOURCE_FILES)" ]; then \
		echo "No source files found"; \
		exit 1; \
	fi
	@echo "Checking $(words $(SOURCE_FILES)) files..."
	clang-format --dry-run --Werror $(SOURCE_FILES)
	@echo "Format check passed!"

# Fix code formatting
format-fix:
	@echo "Fixing code formatting..."
	@if [ -z "$(SOURCE_FILES)" ]; then \
		echo "No source files found"; \
		exit 1; \
	fi
	@echo "Formatting $(words $(SOURCE_FILES)) files..."
	clang-format -i $(SOURCE_FILES)
	@echo "Code formatting applied!"

# Run coverage tests
coverage: configure
	@echo "Running coverage tests..."
	@mkdir -p $(COVERAGE_DIR)
	
	# Build with coverage flags
	cmake --build $(BUILD_DIR)
	
	# Initialize coverage counters
	lcov --directory $(BUILD_DIR) --zerocounters --ignore-errors unused
	
	# Run tests
	ctest --test-dir $(BUILD_DIR) --output-on-failure
	
	# Capture coverage data
	lcov --directory $(BUILD_DIR) \
		--capture \
		--output-file $(COVERAGE_INFO) \
		--rc branch_coverage=1 \
		--ignore-errors deprecated,unsupported,unused
	
	# Remove external libraries and test files from coverage
	lcov --remove $(COVERAGE_INFO) \
		'*/tests/*' \
		'*/examples/*' \
		'*/build/*' \
		--output-file $(COVERAGE_INFO).clean \
		--rc branch_coverage=1 \
		--ignore-errors deprecated,unsupported,unused
	
	@mv $(COVERAGE_INFO).clean $(COVERAGE_INFO)
	@echo "Coverage data collected at: $(COVERAGE_INFO)"

# Generate HTML coverage report
coverage-report: coverage
	@echo "Generating HTML coverage report..."
	@mkdir -p $(COVERAGE_HTML)
	
	genhtml $(COVERAGE_INFO) \
		--output-directory $(COVERAGE_HTML) \
		--title "BFC Coverage Report" \
		--show-details \
		--rc branch_coverage=1 \
		--ignore-errors deprecated,unsupported,unused
	
	@echo "Coverage report generated at: $(COVERAGE_HTML)/index.html"
	@echo "Open with: open $(COVERAGE_HTML)/index.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

# Run static analysis with cppcheck
cppcheck:
	@echo "Running static analysis with cppcheck..."
	@which cppcheck > /dev/null || (echo "Error: cppcheck not found. Install with: apt-get install cppcheck" && exit 1)
	cppcheck --enable=all --inconclusive --xml --xml-version=2 \
		--suppress=missingIncludeSystem \
		--suppress=unmatchedSuppression \
		src/ include/ 2> cppcheck.xml || true
	@echo "Static analysis complete. Results saved to cppcheck.xml"
	@echo "To view results in terminal:"
	@echo "  cppcheck --enable=all --inconclusive src/ include/"

# Convenience aliases
fmt-check: format-check
fmt-fix: format-fix
fmt: format-fix
cov: coverage
cov-report: coverage-report