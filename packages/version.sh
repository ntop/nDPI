#!/usr/bin/env sh

SCRIPTPATH="$(cd "$(dirname "$0")" || exit 1; pwd -P)"
RELEASE="$(cd "${SCRIPTPATH}" || exit 1; < ../configure.ac grep C_INIT | cut -c 20- | rev | cut -c 3- | rev)"
MAJOR_RELEASE="$(cd "${SCRIPTPATH}" || exit 1; < ../configure.ac grep C_INIT | cut -c 20- | rev | cut -c 3- | rev | cut -d. -f1)"
REVISION="$(cd "${SCRIPTPATH}" || exit 1; git rev-list --all | wc -l | tr -d '[[:space:]]')"

get_release() {
	echo "${RELEASE}"
	exit 0
}

get_major_release() {
	echo "${MAJOR_RELEASE}"
	exit 0
}

get_revision() {
	echo "${REVISION}"
	exit 0
}

get_version() {
	echo "${RELEASE}-${REVISION}"
	exit 0
}

case "$1" in
  --release)
	get_release;
	;;
  --major-release)
	get_major_release;
	;;
  --revision)
	get_revision;
	;;
  --version)
	get_version;
	;;
  *)
	echo "Usage: ${0} {--release|--major-release|--revision|--version}"
	exit 1
esac

exit 0
