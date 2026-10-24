What's Inside
-------------

This directory contains list of Internet domain names that are loaded
by ndpiReader with -G <lists directory>

File Name Format
----------------

The file name format is <category id>_<string>.list
The category id list can be found in src/include/ndpi_typedefs.h


Domain Suffix List
------------------

public_suffix_list.dat can be downloaded from
https://publicsuffix.org/list/public_suffix_list.dat, and
it contains the list of domain suffixes

Two Namespaces
--------------

The files in THIS directory are domain lists named <category id>_<string>.list
and are loaded with -G. IP lists that name a PROTOCOL live in the protocols/
subdirectory, are named <protocol id>_<string>.list, and are loaded with
--protocols-list-dir. A file placed in the wrong directory is silently ignored:
see protocols/README.md before adding one.

