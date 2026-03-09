USDT Probes
===========

nDPI supports `USDT <https://lwn.net/Articles/753601/>`_ (User-level Statically Defined Tracing)
probes for zero-overhead dynamic tracing in production. USDT probes compile to a single NOP
instruction and have no runtime cost when not actively being traced. External tools like
``bpftrace``, ``perf``, and ``SystemTap`` can attach to these probes at runtime without restarting
the application.

Building with USDT Support
--------------------------

Install the required header (Linux):

.. code-block:: bash

   # Debian/Ubuntu
   sudo apt-get install systemtap-sdt-dev

   # RHEL/CentOS/Fedora
   sudo dnf install systemtap-sdt-devel

Then configure nDPI with USDT enabled:

.. code-block:: bash

   ./autogen.sh
   ./configure --enable-usdt-probes --enable-debug-build
   make

.. note::

   On macOS, ``sys/sdt.h`` is provided by the system. On platforms where it is
   unavailable, the probes compile to no-ops and have zero impact.

.. note::

   When ``--enable-usdt-probes`` is configured, nDPI automatically tries to embed
   a ``.BTF`` ELF section (requires GCC 10.1+ or Clang 10+). This lets bpftrace
   resolve ``struct ndpi_flow_struct`` fields by name without any ``--include`` flags,
   provided the binary path is used explicitly in the probe specification (see
   `Struct field access via BTF`_ below). On older compilers the section is simply
   absent and the scalar arguments (``arg0``–``arg3``) remain fully usable.

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
     - Fires exactly once per flow when classification is finalized.
       Covers all exit paths: successful detection, giveup, max-packets,
       nBPF match, and extra-dissector completion.
       The scalar arguments allow fast filtering in bpftrace predicates;
       ``arg4`` provides access to all other flow fields when needed.
   * - ``hostname_set``
     - | ``arg0``: hostname string (``char *``)
       | ``arg1``: flow pointer (``struct ndpi_flow_struct *``)
     - Fires when a hostname/SNI is extracted from a flow.
       Covers all protocols that resolve hostnames: TLS (SNI), DNS,
       HTTP (Host header), QUIC, NetBIOS, DHCP, STUN, and others.
       The hostname is provided directly as a string for convenience;
       the flow pointer gives access to all other flow fields.

bpftrace Notes
--------------

Struct field access via BTF
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When nDPI is built with a compiler that supports ``-gbtf`` (GCC 10.1+, Clang 10+),
the binary contains a ``.BTF`` ELF section with full type information. bpftrace can
use this to resolve ``struct ndpi_flow_struct`` fields by name — **without any**
``--include`` **flags** — as long as the full binary path is given in the probe
specification:

.. code-block:: bash

   # Use the full path (not :: shorthand) so bpftrace reads BTF from the binary
   bpftrace -e 'usdt:./example/ndpiReader:ndpi:flow_classified {
     $flow = (struct ndpi_flow_struct *)arg4;
     if ($flow->risk != 0) { @risky[arg0] = count(); }
   }'

You can verify whether the ``.BTF`` section is present:

.. code-block:: bash

   readelf -S example/ndpiReader | grep '\.BTF'

See the `bpftrace USDT documentation
<https://github.com/bpftrace/bpftrace/blob/master/docs/reference_guide.md#usdt>`_
and the `BTF specification <https://docs.kernel.org/bpf/btf.html>`_ for further
details.

Predicates vs. action blocks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

bpftrace predicates (``/condition/``) work well for filtering on scalar arguments
(``arg0``–``arg3`` in ``flow_classified``):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 91/ { ... }'

Filtering on struct fields via a pointer (e.g. ``arg4`` or ``arg1`` in
``hostname_set``) is **not supported in predicates**. User-space pointer
dereferences require ``bpf_probe_read_user()`` internally, which bpftrace only
generates inside action blocks — not in the predicate expression. Attempting it
will either fail to compile or silently misbehave.

Use an ``if`` statement inside the action block instead:

.. code-block:: bash

   bpftrace -e 'usdt:/path/to/ndpiReader:ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @dns[str(arg0)] = count();
     }
   }'

See the `bpftrace reference guide
<https://github.com/bpftrace/bpftrace/blob/master/docs/reference_guide.md>`_
for full details on predicate and action block semantics.

bpftrace Examples
-----------------

List available probes:

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

Count unknown/unclassified flows:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 0/ {
     @unknown = count();
   }'

Flow classification rate (flows/sec):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     @ = count();
   } interval:s:1 { print(@); clear(@); }'

Filter by specific protocol (e.g., TLS = 91):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg0 == 91/ {
     @tls[arg1] = count();
   }'

Flows classified as SocialNetwork (category 6):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified /arg3 == 6/ {
     @social[arg0, arg1] = count();
   }'

Flows with non-zero risk bitmap (requires ``arg4`` / debug symbols):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:flow_classified {
     $flow = (struct ndpi_flow_struct *)arg4;
     if ($flow->risk != 0) {
       @risky[arg0] = count();
     }
   }'

hostname_set Examples
^^^^^^^^^^^^^^^^^^^^^

Real-time hostname log:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
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

   bpftrace -e 'usdt::ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @dns[str(arg0)] = count();
     }
   }'

TLS SNI extraction in real time (TLS = 91):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 91) {
       printf("TLS SNI: %s\n", str(arg0));
     }
   }'

Hostnames with their application protocol breakdown:

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     @host_app[str(arg0), $flow->detected_protocol_stack[1]] = count();
   }'

Hostname resolution rate (hostnames/sec):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     @ = count();
   } interval:s:1 { print(@); clear(@); }'

Detect potential DGA activity (short hostnames with many unique values):

.. code-block:: bash

   bpftrace -e 'usdt::ndpi:hostname_set {
     $flow = (struct ndpi_flow_struct *)arg1;
     if ($flow->detected_protocol_stack[0] == 5) {
       @unique_dns = count();
     }
   } interval:s:10 {
     printf("Unique DNS hostnames in last 10s: %d\n", @unique_dns);
     clear(@unique_dns);
   }'

Correlate hostnames with protocol classification (combine both probes):

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

- **When not tracing:** zero overhead. Probes compile to a single NOP instruction.
- **When actively tracing:** approximately 2-5 microseconds per probe hit, depending on
  the tracing tool and the complexity of the attached script.
- Both probes fire once per flow (not per packet), so even under active tracing the
  overhead is negligible for typical traffic volumes.
