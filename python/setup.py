"""
------------------------------------------------------------------------------------------------------------------------
setup.py
Copyright (C) 2011-22 - ntop.org
This file is part of nDPI, an open source deep packet inspection library.
nDPI is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
nDPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

from setuptools import setup
import os


this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name="ndpi",
    version='4.3.0',
    url='https://www.ntop.org/products/deep-packet-inspection/ndpi/',
    license='LGPLv3',
    description="Open and Extensible LGPLv3 Deep Packet Inspection Library",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Zied Aouini',
    author_email='aouinizied@gmail.com',
    packages=['ndpi'],
    setup_requires=["cffi>=1.15.0"],
    cffi_modules=["ndpi/ndpi_build.py:ffi_builder"],
    install_requires=["cffi>=1.15.0"],
    platforms=["Linux",
               "Mac OS-X",
               "Windows",
               "Unix"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: System :: Networking :: Monitoring',
    ],
    project_urls={
        'GitHub': 'https://github.com/ntop/nDPI',
    }
)
