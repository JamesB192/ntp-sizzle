"""Build a PyPI package containing library and scripts for NTPsec use."""

from pathlib import Path
from setuptools import Extension, find_packages, setup

this_directory = Path(__file__).parent
long_description = (this_directory / "README.markdown").read_text()

setup(
    name='ntp-sizzle',
    version='2024.04.22',
    description='A standalone fork of NTP tools originally from NTPsec',
    author='James Browning',
    author_email='JamesB.fe80@gmail.com',
    maintainer='James Browning',
    maintainer_email='JamesB.fe80@gmail.com',
    license='BSD-2-Clause License',
    url='https://github.com/JamesB192/ntp-sizzle.git',
    long_description=long_description,
    long_description_content_type="text/markdown",
    ext_modules=[
        Extension(
            name="ntp.c",
            sources=["ntp_c.c"],
            extra_compile_args=["-DPYEXT=1"],
        ),
    ],
    install_requires=[
        'cprofile'
        'crptography',
        'curses',
        'gpsd',
        'locale',
        'putil',
    ],
    packages=find_packages(
        where='.',  # '.' by default
        include=['ntp*'],  # ['*'] by default
        exclude=['ntp.tests'],  # empty by default
    ),
    scripts=[
        'scripts/ntpkeygone',
        'scripts/ntpdig',
        'scripts/ntploggps',
        'scripts/ntplogtemp',
        'scripts/ntpmon',
        'scripts/ntpq',
        'scripts/ntpsnmpd',
        'scripts/ntpsweep',
        'scripts/ntptrace',
        'scripts/ntpviz',
        'scripts/ntpwait',
    ],
    classifiers=[
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Development Status :: 5 - Production/Stable',        
    ],
    project_urls = {
        'Bug Tracker': 'https://github.com/jamesb192/ntp-sizzle',
        'IRC': 'https://web.libera.chat/',
        'Project': 'https://github.com/jamesb192/ntp-sizzle',
        'TipLink': 'https://www.patreon.com/JamesB192',
    }
)
