#!/usr/bin/env bash

printf 'Running script: %s\n' "$(basename "${0}")" >&2

function check_http_response()
{
    http_response="${1}"

    if [ "${http_response}" != "200" ]; then
        printf '%s error: %s\n' "${0}" "HTTP Response code ${http_response}; you probably need to update the list url!" >&2
        exit 1
    fi
}

function is_file_empty()
{
    file="${1}"

    if [ ! -r "${file}" ]; then
        printf '%s error: %s\n' "${0}" "file ${file} not found or not readable!" >&2
        exit 1
    fi

    if [ "$(< "${file}" wc -c)" -eq 0 ]; then
        printf '%s error: %s\n' "${0}" "file ${file} empty!" >&2
        exit 1
    fi
}

function is_str_empty()
{
    str="${1}"
    errmsg="${2}"

    if [ -z "${str}" ]; then
        printf '%s error: %s\n' "${0}" "${errmsg}" >&2
        exit 1
    fi
}
