#!/bin/bash
#
# MASTR Test Coverage Generation Script
# Runs unit tests and generates HTML coverage report
#
# Usage:
#   ./generate_coverage.sh         # Run tests and generate coverage
#   ./generate_coverage.sh clean   # Clean coverage data

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== MASTR Test Coverage Generation ===${NC}"

# Check if lcov/genhtml are installed
if ! command -v lcov &> /dev/null; then
    echo -e "${RED}ERROR: lcov not found. Install with: sudo apt-get install lcov${NC}"
    exit 1
fi

if ! command -v genhtml &> /dev/null; then
    echo -e "${RED}ERROR: genhtml not found. Install with: sudo apt-get install lcov${NC}"
    exit 1
fi

# Clean mode
if [ "$1" = "clean" ]; then
    echo -e "${YELLOW}Cleaning coverage data...${NC}"
    cd build 2>/dev/null || true
    rm -f *.gcda *.gcno coverage.info coverage_filtered.info
    rm -rf coverage_html
    cd ..
    echo -e "${GREEN}Coverage data cleaned.${NC}"
    exit 0
fi

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    echo -e "${YELLOW}Creating build directory...${NC}"
    mkdir build
fi

cd build

# Configure with coverage enabled
echo -e "${YELLOW}Configuring build with coverage enabled...${NC}"
cmake .. -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug

# Build tests
echo -e "${YELLOW}Building tests...${NC}"
make clean
make

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
./run_tests

# Check test result
if [ $? -ne 0 ]; then
    echo -e "${RED}TESTS FAILED! Coverage report not generated.${NC}"
    exit 1
fi

echo -e "${GREEN}All tests passed!${NC}"

# Generate coverage report
echo -e "${YELLOW}Generating coverage report...${NC}"
make coverage 2>&1 | grep -v "WARNING:"

# Display summary
echo ""
echo -e "${GREEN}=== Coverage Report Generated ===${NC}"
echo -e "HTML report: ${GREEN}build/coverage_html/index.html${NC}"
echo ""
echo -e "To view report, run:"
echo -e "  ${YELLOW}xdg-open build/coverage_html/index.html${NC}   # Linux"
echo -e "  ${YELLOW}open build/coverage_html/index.html${NC}       # macOS"
echo ""

# Extract coverage percentage (if possible)
if [ -f "coverage_filtered.info" ]; then
    COVERAGE=$(lcov --summary coverage_filtered.info 2>&1 | grep "lines" | grep -oP '\d+\.\d+(?=%)')
    if [ ! -z "$COVERAGE" ]; then
        echo -e "Overall line coverage: ${GREEN}${COVERAGE}%${NC}"
    fi
fi

echo ""
echo -e "${GREEN}Done!${NC}"
