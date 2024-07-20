# Python Bindings Development Guide

The aim of this document is to guide when extending these bindings with additional nDPI API.
In the following we suppose that we want to add the following API to ndpi python package.

``` c
int ndpi_des_init(struct ndpi_des_struct *des, double alpha, double beta, float significance);
```

## Add it to NDPI_APIS Python definition

[**NDPI_APIS**][py_ndpi_api] must be updated with the new API you want to add.

## Regenerate bindings

``` bash
python3 setup.py install
```

## That's it!

Now this API can be called and used on python side

``` python
from ndpi import lib, ffi

des = ffi.new("struct ndpi_des_struct *")
alpha = 0.9
beta = 0.5
lib.ndpi_des_init(des, alpha, beta, 0.05)
```

[py_ndpi_api]: https://github.com/ntop/nDPI/blob/c47d710d8e5281fff2f1f90ff5462c16ac91d50c/python/ndpi/ndpi_build.py#L49