# ndpi

This package contains Python bindings for nDPI. nDPI is an Open and Extensible LGPLv3 Deep Packet Inspection Library.

**ndpi** is implemented using [**CFFI**][cffi] (out-of-line API mode). Consequently, it is fast and [**PyPy**][pypy] 
compliant.

## Installation

### Build nDPI

``` bash
git clone --branch dev https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo make install
```

### Install ndpi package

``` bash
cd python
# IMPORTANT: nDPI Bindings requires Python version >= 3.7
python3 -m pip install --upgrade pip
python3 -m install -r dev_requirements.txt
python3 -m pip install .
```

## Usage

### API
``` python
from ndpi import NDPI, NDPIFlow

nDPI = NDPI()

# You per flow processing here 
# ...

ndpi_flow = NDPIFlow()
nDPI.process_packet(ndpi_flow, ip_bytes, time_ms)
nDPI.giveup(ndpi_flow) # If you want to guess it instead (DPI fallback)
```

### Example Application

[ndpi_example.py][ndpi_example] is provided to demonstrate how **ndpi** can be integrated within your Python application.

``` bash
Using nDPI 4.3.0-3532-8dd70b70
usage: ndpi_example.py [-h] [-u] input

positional arguments:
  input                 input pcap file path

optional arguments:
  -h, --help            show this help message and exit
  -u, --include-unknowns
```

Example with a Skype capture file

``` bash
python3 ndpi_example.py -u ../tests/pcap/skype.pcap
```

## Related projects

The provided example is for demo purposes only, For additional features (live capture, multiplatform support, 
multiprocessing, ML based classification, system visibility, etc.), please check nDPI based 
framework, [**NFStream**][nfstream].
## License

This project is licensed under the LGPLv3 License - see the [**License**][license] file for details.

[license]: https://github.com/ntop/nDPI/blob/dev/COPYING
[cffi]: https://cffi.readthedocs.io/en/latest/
[pypy]: https://www.pypy.org/
[nfstream]: https://github.com/nfstream/nfstream
[ndpi_example]: https://github.com/ntop/nDPI/blob/dev/python/ndpi_example.py
