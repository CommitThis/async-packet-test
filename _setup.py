""" SetupTool Entry Point """
import sys
from pathlib import Path
from shutil import copy2

import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

install_requirements = [
    'scapy',
    'pytest',
    'pytest-cov'
]


# def get_setuptools_ver():
# 	ver_components = setuptools.__version__.split('.')[:3]
# 	return tuple([int(x) for x in ver_components])


# if get_setuptools_ver() < (40, 1, 0):
# 	print('Setuptools version too old, v40.1.0 and above required. Might be able to upgrade with')
# 	print('\tpip install --upgrade setuptools')
# 	print('Or use provided setup.sh script.')
# 	sys.exit(1)

if sys.version_info < (3, 7):
	install_requirements.append('importlib_resources')
	install_requirements.append('wheel')

setuptools.setup(
    name="async_packet_test",
    version="0.0.1",
    author="CommitThis",
    author_email="gdavey@committhis.co.uk",
    description="Simple async packet testing library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    # url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_namespace_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        'License :: OSI Approved :: Apache Software License',
    ],

    python_requires='>=3.6',
	install_requires=install_requirements,

)