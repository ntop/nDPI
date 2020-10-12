#!/bin/sh

cd "$(dirname "${0}")"

UNIT="./unit/unit"

RC=0

check_unit() {

    case "$CXXFLAGS" in
	# Skipping tests with sanitizer enabled due to use-of-uninitialized-value in json-c
	*sanitize* )
	    echo "Skipping unit tests for this environment"
	    return
	    ;;
	* )
	    echo ""
	    echo "Running unit tests.."
	    ;;
    esac

    $UNIT
    UNIT_RC=$?
    if [ $UNIT_RC -ne 0 ]; then
	RC=1
    fi
}

check_unit

exit $RC
