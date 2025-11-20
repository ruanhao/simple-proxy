#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# Description:

set -e

# 默认值
WITH_COVERAGE=false
HTML_REPORT=false
VERBOSE=false
POSITIONAL_ARGS=()
TESTS_DIR="tests"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            echo "Usage: $0 [options] [file] [function]"
            echo ""
            echo "Note:"
            echo "  Proxy 127.0.0.1:47017 to the remote MongoDB server for integration testing purposes."
            echo ""
            echo "Options:"
            echo "  --with-coverage, -c   Enable code coverage reporting"
            echo "  --integration, -i     Run integration tests"
            echo "  --html-report, -t     Generate HTML coverage report"
            echo "  --verbose, -v         Enable verbose output"
            echo "  --help, -h            Show this help message"
            exit 0
            ;;
        --integration|-i)
            TESTS_DIR="integration_tests"
            shift
            ;;
        --with-coverage|-c)
            WITH_COVERAGE=true
            shift
            ;;
        --html-report|-t)
            HTML_REPORT=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            export SMBAI_VERBOSE_TEST=1
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

FILE="${POSITIONAL_ARGS[0]}"
FUNC="${POSITIONAL_ARGS[1]}"


TARGET="$TESTS_DIR/"
if [[ -n "$FILE" ]]; then
    TARGET="$TESTS_DIR/$FILE"
    if [[ -n "$FUNC" ]]; then
        TARGET="${TARGET}::${FUNC}"
    fi
fi


PYTEST_CMD=("pytest")

if $WITH_COVERAGE; then
    PYTEST_CMD+=("--cov=." "--cov-report=term-missing")
    if $HTML_REPORT; then
        PYTEST_CMD+=("--cov-report=html")
    fi
else
    if $HTML_REPORT; then
        PYTEST_CMD+=("--html=report.html" "--self-contained-html")
    else
        PYTEST_CMD+=("-s")
    fi
fi

if $VERBOSE; then
    PYTEST_CMD+=("-vv")
fi


if [[ -n "$TARGET" ]]; then
    PYTEST_CMD+=("$TARGET")
fi


echo ">>> Run: ${PYTEST_CMD[*]}"
"${PYTEST_CMD[@]}"
