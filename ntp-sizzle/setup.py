"""Build a PyPI package containing library and scripts for NTPsec use."""

from setuptools import Extension, find_packages, setup

setup(
    name='ntp-sizzle',
    version='2024.04.21',
    description='A standalone fork of NTP tools originally from NTPsec',
    author='James Browning',
    author_email='JamesB.fe80@gmail.com',
    maintainer='James Browning',
    maintainer_email='JamesB.fe80@gmail.com',
    license='BSD 2-Clause License',
    url='https://github.com/JamesB192/ntp-sizzle.git',
    long_description="README.md",
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'License :: OSI Approved :: BSD-2-Clause',
        'Operating System :: POSIX',
        'Development Status :: 5 - Production/Stable',        
    ],
    project_urls = {
        # 'Bug Tracker':' 'https://github.com/jamesb192/ntp-sizzle',
        'IRC': 'https://web.libera.chat/',
        # 'Project': 'https://github.com/jamesb192/ntp-sizzle',
        # 'Support': 'https://gpsd.io/SUPPORT.html',
        'TipLink': 'https://www.patreon.com/JamesB192',
    }
)

"""
[metadata]
long_description = file: README.md
long_description_content_type = text/markdown

[options]
package_dir =
    = src
packages = gps
scripts = @SCRIPTS@

"""
