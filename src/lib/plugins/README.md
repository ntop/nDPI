
# Configuration

You need to make sure that the libndpi.so.x.x.x is available in the LD_LIBRARY_PATH (or DYLD_LIBRARY_PATH on macOS)  path

export DYLD_LIBRARY_PATH=<directory where libndpi.so is stored (e.g. nDPI/src/lib/)

On Linux, you need to use LD_LIBRARY_PATH, instead

Usage example:
- ./example/ndpiReader --plugins-dir src/lib/plugins/ -i tests/pcap/zoom.pcap