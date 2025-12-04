#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# Description:

set -e

VERBOSE=false
POSITIONAL_ARGS=()
TESTS_DIR="tests"
STDOUT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            echo "Usage: $0 [options] [file] [function]"
            echo ""
            echo "Options:"
            echo "  --integration, -i     Run integration tests"
            echo "  --verbose, -v         Enable verbose output"
            echo "  --help, -h            Show this help message"
            exit 0
            ;;
        --integration|-i)
            TESTS_DIR="integration_tests"
            shift
            ;;
        --stdout|-s)
            STDOUT=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
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
if $STDOUT; then
    PYTEST_CMD+=("-s")
fi

if $VERBOSE; then
    PYTEST_CMD+=("-vv")
fi

if [[ -n "$TARGET" ]]; then
    PYTEST_CMD+=("$TARGET")
fi


echo ">>> Run: ${PYTEST_CMD[*]}"
"${PYTEST_CMD[@]}"
