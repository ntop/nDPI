USDT Probes
===========

nDPI supports `USDT <https://lwn.net/Articles/753601/>`_ (User-level Statically Defined Tracing)
probes for zero-overhead dynamic tracing in production environments. Each probe compiles down to a
single NOP instruction and incurs no runtime cost when not actively traced. External tools such as
``bpftrace``, ``perf``, and ``SystemTap`` can attach to these probes at runtime without restarting
or recompiling the application.

Building with USDT Support
--------------------------

Install the required development headers (Linux):

.. code-block:: bash

   # Debian/Ubuntu
   sudo apt-get install systemtap-sdt-dev dwarves

   # RHEL/CentOS/Fedora
   sudo dnf install systemtap-sdt-devel dwarves

Then configure and build nDPI with USDT support enabled:

.. code-block:: bash

   ./autogen.sh
   ./configure --enable-usdt-probes --enable-debug-build
   make

.. note::

   On macOS, ``sys/sdt.h`` is provided by the system. On platforms where it is
   unavailable, the probes compile to no-ops and have no impact whatsoever.

.. note::

   To allow bpftrace to resolve ``struct ndpi_flow_struct`` fields by name without
   any ``--include`` flags, embed BTF into the binaries after building using
   ``pahole -J`` (from the ``dwarves`` package). See `Struct field access`_
   below. Without BTF, the scalar arguments remain fully usable.

Available Probes
----------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Probe Name
     - Arguments
     - Description
   * - ``flow_classified``
     - | ``arg0``: master protocol ID (``u16``)
       | ``arg1``: application protocol ID (``u16``)
       | ``arg2``: confidence level (``enum``)
       | ``arg3``: category (``enum``)
       | ``arg4``: flow pointer (``struct ndpi_flow_struct *``)
     - Fires exactly once per flow when classification is finalised.
       Covers all exit paths: successful detection, give-up, max-packets
       reached, nBPF match, and extra-dissector completion.
       The scalar arguments (``arg0``–``arg3``) support efficient filtering
       inside bpftrace predicates; ``arg4`` provides access to all remaining
       flow fields when deeper inspection is required.
   * - ``hostname_set``
     - | ``arg0``: hostname string (``char *``)
       | ``arg1``: flow pointer (``struct ndpi_flow_struct *``)
     - Fires whenever a hostname or SNI is extracted from a flow.
       Covers all protocols that carry a hostname: TLS (SNI), DNS,
       HTTP (Host header), QUIC, NetBIOS, DHCP, STUN, and others.
       The hostname is passed directly as a string for convenience;
       the flow pointer provides access to all other flow fields.
   * - ``fragment_ipv4``
     - | ``arg0``: pointer to IPv4 header (``struct ndpi_iphdr *``)
     - Fires when an IPv4 packet processed by the library is fragmented
       at the IP layer.
   * - ``fragment_ipv6``
     - | ``arg0``: pointer to IPv6 header (``struct ndpi_ipv6hdr *``)
     - Fires when an IPv6 packet processed by the library is fragmented
       at the IP layer.

bpftrace Notes
--------------

Struct field access
^^^^^^^^^^^^^^^^^^^^

To dereference userspace pointers (for example, ``struct ndpi_flow_struct``
passed as ``arg1`` in the ``hostname_set`` probe) you must embed BTF information
into the shared library or executable. The recommended approach is to run
``pahole -J`` (from the ``dwarves`` package) as a post-build step: it reads the
DWARF debug information already present in the binary and inserts a ``.BTF``
section with full type information.

.. code-block:: bash

   # Debian/Ubuntu
   sudo apt-get install dwarves

   # RHEL/CentOS/Fedora
   sudo dnf install dwarves

   ./configure --enable-usdt-probes --enable-debug-build
   make
   pahole -J src/lib/libndpi.so
   pahole -J example/ndpiReader

Once the ``.BTF`` section is present, bpftrace can resolve
``struct ndpi_flow_struct`` fields by name — **without any** ``--include``
**flags** — provided the full binary path is used in the probe specification.
Note that the ``::`` shorthand does not trigger BTF lookup:

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:flow_classified {
     $flow = (struct ndpi_flow_struct *)arg4;
     if ($flow->risk != 0) { @risky[arg0] = count(); }
   }'

Verify that the section is present with:

.. code-block:: bash

   readelf -S example/ndpiReader | grep '\.BTF'


.. _btf-pitfalls:

BTF Generation — Known Issues and Workarounds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**C11 ``_Atomic`` types break pahole BTF encoding**

nDPI's bundled CRoaring library uses ``_Atomic`` qualifiers, which the
compiler emits as ``DW_TAG_atomic_type`` entries in DWARF. All released
versions of ``pahole`` (including 1.31) abort BTF encoding upon encountering
this tag, even when ``--btf_encode_force`` is passed::

   Unsupported DW_TAG_atomic_type(0x47): type: 0x153c6
   Encountered error while encoding BTF.

The workaround used in nDPI's CI pipeline is to rebuild with
``CROARING_ATOMIC_IMPL=1``, which selects a non-atomic code path and
eliminates the offending DWARF entries:

.. code-block:: bash

   CFLAGS="-DCROARING_ATOMIC_IMPL=1" ./configure \
       --enable-usdt-probes --enable-debug-build
   make

**Fallback: generate a C header with bpftool**

Even with BTF information correctly embedded, pointer dereferences may still
fail with::

    stdin:1:65-93: ERROR: Cannot resolve unknown type "struct ndpi_flow_struct"

In this case, generate a C header from the BTF information and pass it to
bpftrace with ``--include``:

.. code-block:: bash

   # Generate a C header containing the full layout of the userspace structures
   bpftool btf dump file /path/to/ndpiReader format c > ndpi_types.h

   # Pass the header to bpftrace
   sudo bpftrace --include ndpi_types.h \
     -e 'usdt:/path/to/ndpiReader:ndpi:flow_classified {
       $flow = (struct ndpi_flow_struct *)arg4;
       if ($flow->risk != 0) { @risky[arg0] = count(); }
     }'

bpftrace Map Size Limits
^^^^^^^^^^^^^^^^^^^^^^^^

When tracing long or high-throughput captures, bpftrace maps can become full
and emit a kernel-level ``E2BIG`` warning::

   WARNING: Map full; can't update element.
   Additional Info - helper: map_update_elem, retcode: -7

Increase the map key limit via the environment variable (supported by all
recent bpftrace versions):

.. code-block:: bash

   sudo BPFTRACE_MAX_MAP_KEYS=100000 bpftrace --include ndpi_types.h \
     -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
       @top[str(arg0)] = count();
     }'

Newer bpftrace builds also accept a ``config`` block at the top of the
script:

.. code-block:: bash

   sudo bpftrace --include ndpi_types.h \
     -e 'config = { max_map_keys = 100000 }
   usdt:/path/to/ndpiReader:ndpi:hostname_set {
     @top[str(arg0)] = count();
   }'


Predicates vs. action blocks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

bpftrace predicates (``/condition/``) work well for filtering on scalar arguments
(``arg0``–``arg3`` in ``flow_classified``):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 91/ { ... }'

Filtering on struct fields via a pointer (e.g., ``arg4`` in ``flow_classified``
or ``arg1`` in ``hostname_set``) is **not supported in predicates**.

Use an ``if`` statement inside the action block instead:

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @dns[str(arg0)] = count();
     }
   }'

bpftrace Examples
-----------------

.. note::

   Examples that dereference a userspace pointer (``arg4`` in ``flow_classified``,
   ``arg1`` in ``hostname_set``) require either a ``.BTF`` section embedded in
   the binary via ``pahole -J`` **or** an explicit ``--include ndpi_types.h``
   header (generated via ``bpftool btf dump ... format c``). See
   `BTF Generation — Known Issues and Workarounds`_ above.

   Scalar-only examples (those using only ``arg0``–``arg3`` in ``flow_classified``
   or ``arg0`` in ``hostname_set``, without struct dereference) work without BTF
   or headers and can use the ``::`` shorthand.


List all available probes:

.. code-block:: bash

   bpftrace -l "usdt:./src/lib/.libs/libndpi.so:ndpi:*"

flow_classified Examples
^^^^^^^^^^^^^^^^^^^^^^^^

Real-time protocol classification log:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     printf("master=%d app=%d confidence=%d category=%d\n",
            arg0, arg1, arg2, arg3);
   }'

Protocol distribution histogram:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     @proto_master[arg0] = count();
   }'

Confidence level breakdown:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     @confidence[arg2] = count();
   }'

Category distribution:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     @category[arg3] = count();
   }'

Count unclassified flows (master protocol == 0):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 0/ {
     @unknown = count();
   }'

Flow classification rate (flows/sec):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     @ = count();
   } interval:s:1 { print(@); clear(@); }'

Filter by a specific protocol (e.g., TLS = 91):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 91/ {
     @tls[arg1] = count();
   }'

Flows classified under SocialNetwork (category 6):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg3 == 6/ {
     @social[arg0, arg1] = count();
   }'

Flows with a non-zero risk bitmap (requires BTF or ``--include``):

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:flow_classified {
     $flow = (struct ndpi_flow_struct *)arg4;
     if ($flow->risk != 0) {
       @risky[arg0] = count();
     }
   }'

hostname_set Examples
^^^^^^^^^^^^^^^^^^^^^

Real-time hostname log:

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     printf("%s (master=%d app=%d)\n",
            str(arg0),
            $flow->detected_protocol_stack[0],
            $flow->detected_protocol_stack[1]);
   }'

Top hostnames by flow count:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     @top[str(arg0)] = count();
   }'

Monitor a specific domain (e.g., all ``*.google.com`` traffic):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set /strcontains(str(arg0), "google.com")/ {
     @google[str(arg0)] = count();
   }'

Hostnames resolved via DNS only (DNS = 5):

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @dns[str(arg0)] = count();
     }
   }'

TLS SNI extraction in real time (TLS = 91):

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 91) {
       printf("TLS SNI: %s\n", str(arg0));
     }
   }'

Hostname-to-application-protocol breakdown:

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     @host_app[str(arg0), $flow->detected_protocol_stack[1]] = count();
   }'

Hostname resolution rate (hostnames/sec):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     @ = count();
   } interval:s:1 { print(@); clear(@); }'

Detect potential DGA activity (count unique DNS hostnames over time):

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @unique_dns = count();
     }
   } interval:s:10 {
     printf("Unique DNS hostnames in last 10s: %d\n", @unique_dns);
     clear(@unique_dns);
   }'

Correlate hostnames with protocol classification (combining both probes):

.. code-block:: bash

   bpftrace -e '
   usdt::ndpi:hostname_set  { @host[tid] = str(arg0); }
   usdt::ndpi:flow_classified /@host[tid] != ""/ {
     printf("host=%s master=%d app=%d conf=%d cat=%d\n",
            @host[tid], arg0, arg1, arg2, arg3);
     delete(@host[tid]);
   }'

perf Example
------------

Record probe hits with ``perf``:

.. code-block:: bash

   perf probe -x ./src/lib/.libs/libndpi.so sdt_ndpi:flow_classified
   perf record -e sdt_ndpi:flow_classified -p $(pidof ndpiReader) -- sleep 10
   perf report

Overhead
--------

- **When not tracing:** zero overhead. Each probe compiles to a single NOP instruction.
- **When actively tracing:** approximately 2–5 microseconds per probe hit, depending on
  the tracing tool and the complexity of the attached script.
- ``flow_classified`` and ``hostname_set`` fire at most once per flow (not per packet),
  so their overhead remains negligible even under active tracing at high traffic volumes.
  ``fragment_ipv4`` and ``fragment_ipv6`` fire once per fragmented packet.
