#!/usr/bin/env sh

set -e

SCRIPT_DIR="$(realpath $(dirname ${0}))"
NDPI_LIB="${1:-${SCRIPT_DIR}/../src/lib/libndpi.a}"

if [ ! -r "${NDPI_LIB}" ]; then
    printf '%s\n' "${0}: nDPI static library '$(realpath ${NDPI_LIB})' not found."
    exit 1
fi

FAIL_COUNT=0
CURRENT_OBJECT=''
for line in `nm -P -u "${NDPI_LIB}"`; do
    OBJECT="$(printf '%s' "${line}" | grep -E "^${NDPI_LIB}\[.*\.o\]:" | grep -oE "\[.*\.o\]" || true)"
    if [ ! -z "${OBJECT}" ]; then
        CURRENT_OBJECT="${OBJECT}"
    fi

    #printf '%s\n' "${line}"
    FOUND_SYMBOL="$(printf '%s' "${line}" | grep '^\(malloc\|calloc\|realloc\|free\)$' || true)"

    if [ ! -z "${FOUND_SYMBOL}" ]; then
        SKIP=0
        case "${CURRENT_OBJECT}" in
            '[ndpi_utils.o]'|'[ndpi_memory.o]'|'[roaring.o]') SKIP=1 ;;
        esac

        if [ ${SKIP} -eq 0 ]; then
            FAIL_COUNT="$(expr ${FAIL_COUNT} + 1)"
            printf '%s: %s\n' "${CURRENT_OBJECT}" "${FOUND_SYMBOL}"
        fi
    fi
done

printf 'Unwanted symbols found: %s\n' "${FAIL_COUNT}"
if [ ${FAIL_COUNT} -gt 0 ]; then
    printf '%s\n' 'Please make sure to use only ndpi_malloc/ndpi_calloc/ndpi_realloc/ndpi_free wrapper instead of malloc/calloc/realloc/free'
fi
exit ${FAIL_COUNT}
