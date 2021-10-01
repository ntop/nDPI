What is nDPI
##############

nDPI is a DPI (Deep Packet Inspection) toolkit able to:

- Detect application protocol on traffic flows
- Analize encrypted traffic flows via ET (Encrypted Traffic Analysis)
- Extract selected protocol metadata from traffic
- Implement APIs for analysing traffic

Releases and Features
---------------------

nDPI development lifecycle is typically 6 to 9 months. The history of changes and features implemented by every release, is available on its `Changelog <https://github.com/ntop/nDPI/blob/dev/CHANGELOG.md>`_.


Installation
============

nDPI is open source and available on `GitHub
<https://github.com/ntop/nDPI>`_. In addition, pre-compiled, binary
nDPI packages are available both for Linux and other platforms. Installation
instructions for binary packages are available below.

Installing on Linux
-------------------

Installation instructions can be found at
http://packages.ntop.org/. Development and stable builds are
available. Stable builds are intended for production environments whereas
development builds are intended for testing or early feature access.


Software Updates
================

General instructions for updating the software can be found at
http://packages.ntop.org/ together with the installation instructions.
Depending on the Operating System, nDPI supports also automatic updates
through the GUI as described in the below sections.

Updating the Software on Linux
------------------------------

Instructions for updating the software via command line can be found
at http://packages.ntop.org/. For example on Ubuntu/Debian systems the
below commands will update the repository, check for updates and install
the latest software update if any:

.. code:: bash

   apt-get update
   apt-get upgrade

.. _AvailableVersions:
  
