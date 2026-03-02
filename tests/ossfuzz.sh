#!/usr/bin/env bash
set -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

if [[ "$SANITIZER" != "memory" ]]; then
	#Disable code instrumentation
	CFLAGS_SAVE="$CFLAGS"
	CXXFLAGS_SAVE="$CXXFLAGS"
	unset CFLAGS
	unset CXXFLAGS
	export AFL_NOOPT=1
fi

# build libpcap
tar -xvzf libpcap-1.9.1.tar.gz
cd libpcap-1.9.1
./configure --disable-shared --disable-dbus --without-libnl --disable-rdma --disable-usb
make -j$(nproc)
make install
cd ..

if [[ "$SANITIZER" != "memory" ]]; then
	#Re-enable code instrumentation
	export CFLAGS="${CFLAGS_SAVE}"
	export CXXFLAGS="${CXXFLAGS_SAVE}"
	unset AFL_NOOPT
fi

# Workaround for introspector builds.
# See: google/oss-fuzz#13226.
# See: https://github.com/ossf/fuzz-introspector/pull/2278
# See: https://github.com/google/oss-fuzz/pull/14962
if [[ "$SANITIZER" = "introspector" ]]; then
  curl -O https://patch-diff.githubusercontent.com/raw/ossf/fuzz-introspector/pull/2278.patch
  patch -p1 --directory=/fuzz-introspector/ < 2278.patch
  export FUZZ_INTROSPECTOR_PARALLEL=false
fi

# build project
cd ndpi
#There are two workarounds:
# * pcap stuff + --with-only-libndpi: for introspector builds. As reported in #8939, configure is not able to detect external libraries in introspector builds
# * ADDITIONAL_* stuff: to be able run tests/unit/unit (via chronos/check_tests.sh) even with the previous workaround
./autogen.sh && AR=llvm-ar RANLIB=llvm-ranlib LDFLAGS="-L/usr/local/lib -lpcap" ADDITIONAL_INCS="-I/usr/local/include/json-c/" ADDITIONAL_LIBS="-L/usr/local/lib -ljson-c" ./configure --disable-shared --enable-fuzztargets --with-only-libndpi
make -j$(nproc)
# Copy fuzzers
ls fuzz/fuzz* | grep -v "\." | while read -r i; do cp "$i" "$OUT"/; done
# Copy dictionaries
cp fuzz/*.dict "$OUT"/
# Copy seed corpus
cp fuzz/*.zip "$OUT"/
# Copy options
cp fuzz/*.options "$OUT"/
# Copy configuration files
cp example/*.txt "$OUT"/
cp example/*.csv "$OUT"/
cp example/*.conf "$OUT"/
cp lists/public_suffix_list.dat "$OUT"/
cp fuzz/ipv*_addresses.txt "$OUT"/
cp fuzz/bd_param.txt "$OUT"/
cp fuzz/splt_param.txt "$OUT"/
cp fuzz/random_list.list "$OUT"/
mkdir -p "$OUT"/lists
# Ignore a huge list to speed up init time
find lists/*.list ! -name 100_malware.list -exec cp -t "$OUT"/lists/ {} +
mkdir -p "$OUT"/lists/protocols
find lists/protocols/*.list -exec cp -t "$OUT"/lists/protocols/ {} +
