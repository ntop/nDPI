.. _tcp_fingerprint:

TCP Fingerprint
===============

nDPI computes a fingerprint of the TCP stack that *opened* a connection. It
identifies a stack -- an operating system class -- not an application, and it is
derived from passive observation only: no probing, no active measurement, no
payload.

The format is specified in the repository in ``fingerprint/nDPI_TCP_fingerprint.md``,
next to the reference implementation (``fingerprint/ndpi_tcp_fp.py``). This page is
the developer's-guide view of it: what the library exposes, which knobs control it,
and what the output does and does not claim.

How it is computed
------------------

The fingerprint is taken from the first SYN (a segment with SYN set and ACK
clear) seen on a flow, that is, from the host that initiated the connection.
Three consequences are worth stating up front:

* the server side of a connection is never fingerprinted, because its SYN
  carries the ACK flag;
* a capture that begins after the handshake contains no SYN, so the flow has no
  fingerprint at all;
* behind a proxy, a gateway or a NAT, the fingerprint belongs to the last host
  that opened the connection, not to the application or the user behind it.

Format 0 -- native nDPI (default)
---------------------------------

The fingerprint is ``flags_TTL_window_hash``, where:

``flags``
  The TCP flags of the SYN: ``2`` for a plain SYN, ``194`` (0xC2) for a SYN that
  also sets ECE and CWR, which is what an ECN-capable client sends. ECN support
  is a stack and policy choice, so this field changes without the OS changing.
``TTL``
  The IP TTL of the SYN as observed, and therefore decremented by every router
  on the path.
``window``
  The initial TCP window.
``hash``
  The first eight hex digits of a MurmurHash over the TCP option list, written
  as decimal tokens -- ``2,4,8,1,3:7``, for example, is MSS, window scale, SACK
  permitted, timestamp, and a seven-byte NOP run. Option order, length and
  content all feed the hash, so a stack upgrade that reorders options changes
  the fingerprint.

Examples: ``2_64_64240_789c1d1f`` (Linux), and ``2_64_65535_e76f0f14`` next to
``194_64_65535_e76f0f14``, which are the same host with a non-ECN and an
ECN-capable client.

Format 1 -- MuonFP
------------------

Selected with ``metadata.tcp_fingerprint_format`` = 1: the initial window, then
the TCP option kinds separated by ``-``, then ``:MSS`` and ``:window scale``.
See the `MuonFP project <https://github.com/sundruid/muonfp>`_ for the format
definition. Note that the built-in OS table is expressed in the native format,
so in MuonFP mode the OS hint is ``Unknown`` unless you load a table of your own
in that format.

Raw option list
---------------

With ``metadata.tcp_fingerprint_raw`` (off by default) the option list itself is
exported as ``tcp_fingerprint_raw``, in the same decimal token notation used for
the hash input. This is the readable form of what the hash summarizes.

OS resolution
-------------

The fingerprint is mapped to an ``ndpi_os`` value:

===== ==========================
  id  OS
===== ==========================
  0   Unknown
  1   Windows
  2   macOS / iPadOS / iOS
  3   Android
  4   Linux
  5   FreeBSD
===== ==========================

Two tables feed the mapping:

* the built-in table, ``src/lib/ndpi_os_fingerprint.c.inc``, loaded by
  ``ndpi_load_tcp_fingerprints()`` and in native format only. It is small on
  purpose: an entry is a measured fingerprint, not a guess, and the convention
  in that file is to record the raw option string and the capture it came from
  next to each entry, so the table can be recomputed if the format changes.
  An ``Unknown`` OS therefore means "not in the table", not "not Linux".
* a table of your own, loaded with ``ndpi_load_tcp_fingerprint_file()``, one
  entry per line in the form ``<fingerprint>,<os id>``, or added at runtime with
  ``ndpi_add_tcp_fingerprint()``.

The mapping is available through ``ndpi_get_os_from_tcp_fingerprint()`` and its
name through ``ndpi_print_os_hint()``. Note that ``example/tcp_fingerprints.csv``
is a sample of the file format and is not read by ``ndpiReader``, which has no
option for TCP fingerprint lists; an application that wants operator entries has
to call the loader itself.

Exported fields
---------------

The text dump shows the fingerprint with its resolved OS, the MSS and the TCP
Fast Open state::

  [TCP Fingerprint: 2_64_64240_789c1d1f/Linux][MSS: 1460][TFO: cookie request]

The JSON flow record carries the same information as separate fields:
``tcp_fingerprint``, ``tcp_fingerprint_raw`` (when enabled), ``tcp_mss``,
``tcp_fastopen`` and ``tcp_os`` (the resolved OS name). All of them are absent
when the flow has no SYN, rather than reported as unknown.

Configuration
-------------

The three parameters are ``metadata.tcp_fingerprint``,
``metadata.tcp_fingerprint_raw`` and ``metadata.tcp_fingerprint_format``, listed
with their defaults in :doc:`configuration_parameters`.
