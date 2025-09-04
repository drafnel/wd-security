
# How to build wd-security from source...

## REQUIREMENTS

- libssl-dev -- libcrypto.so
- asciidoc -- a2x utility, for generating the man page
- A working C compiler and development libraries.

If building directly from the git repository, additionally:

- autoconf

## CONFIGURE

Generate the `configure` script (skip if building from a tarball):

    autoreconf --verbose --install --symlink

Run the `configure` script to generate the Makefile:

    ./configure

Or, if a dedicated "build" directory is desired, create one and perform
the configure in there, for example:

    mkdir build && cd build && ../configure

## BUILD

Then run make to compile the sources:

    make -j

## INSTALL

Then install (probably as root):

    sudo make install

## Build a .deb

### Requirements

- dpkg-buildpackage

### Make the deb

    make deb

This should create the following files:

    wd-security_<version>_<arch>.buildinfo
    wd-security_<version>_<arch>.changes
    wd-security_<version>_<arch>.deb
    wd-security_<version>.dsc
    wd-security_<version>.tar.xz
    wd-security-dbgsym_<version>_<arch>.ddeb

Use `dpkg` to install the binary package:

    sudo dpkg -i wd-security_<version>_<arch>.deb
