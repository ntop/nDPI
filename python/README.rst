nDPI Python bindings
--------------------

This directory contains the Python3 bindings for nDPI. We provide both cffi and ctypes based bindings.

**cffi bindings**

Files:

* ndpi.py

Example (using `nfstream <https://github.com/aouinizied/nfstream>`_   package):

.. code-block:: bash

    pip3 install nfstream
    python3 flow_printer.py <interface>
    python3 flow_printer.py <pcap_file>

Code courtesy:

* Zied Aouini

**ctypes bindings**

Files:

* ndpi_typestruct.py
* ndpi_wrap.c
* Makefile.in

Example:

.. code-block:: bash

    pip3 install scapy
    python3 ndpi_example.py <interface>
    python3 ndpi_example.py <pcap_file>

Code courtesy:

* Massimo Puddu
* Zied Aouini
