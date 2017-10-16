This package is a GPL implementation of an iptables and netfilter module for
nDPI integration into the Linux kernel.

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=4KDWWS2B2GBGQ&lc=BR&item_name=betolj%40gmail%2ecom" target="_blank"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif" border="0" alt="PayPal — The safer, easier way to pay online."></a>


The prerequisites are:

- Tested on Ubuntu 14.04.1 LTS (Kernel 3.13.0-37-generic)
- Following packages to compile kernel-modules:
   linux-headers
   iptables-dev >= version 1.4.21-1ubuntu1
   nDPI source package


Compiled kernel features
------------------------

You do not need to do the below steps for Ubuntu 14.04.1 LTS

In order to use nDPI as a kernel module notice that:

- You should ENABLE Netfilter conntrack events (and also enable Advanced
  netfilter features to see it).

In kernel 2.6.34 or greater its defined as:

Connection tracking events
Symbol: NF_CONNTRACK_EVENTS
Location:
-> Networking support
 -> Networking options
  -> Network packet filtering framework (Netfilter)
   -> Core Netfilter Configuration
    -> Netfilter connection tracking support

In kernel 2.6.34 or greater its defined as:

Connection tracking netlink interface
Symbol: NF_CT_NETLINK
Location:
-> Networking support
 -> Networking options
  -> Network packet filtering framework (Netfilter)
   -> Core Netfilter Configuration
    -> Netfilter connection tracking support


Once you have downloaded/installed each package and checked for the above
kernel features you can read the INSTALL file.
