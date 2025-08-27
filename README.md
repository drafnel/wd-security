
# WD Security for Linux w/ auto-unlocking

Manage password protection of Western Digital external drives supported
by the proprietary WD Security software.  All operations are compatible
with the proprietary WD Security software, allowing interoperability
between Windows, Mac and Linux.

## Introduction

Western Digital sells a range of external drives that support 256-bit
AES hardware encryption.  The proprietary WD Security software can be
used to manage the password protection of these drives on Windows or
MacOS.  The following drives are listed as supported:

> Direct Attached Storage (DAS) Drives: My Book, My Book for Mac,
> My Book Duo, WD Drive Plus, My Passport works with USB-C, My Passport,
> My Passport for Mac, My Passport Ultra, My Passport Ultra for Mac,
> My Passport Ultra (USB-C), My Passport Ultra for Mac (USB-C),
> My Passport Ultra Metal, WD Backup Drive Desktop

If a password is configured on any of these drives, then the drive
cannot be accessed.  Once unlocked, the drives will function normally.

## Features

Supports unlocking, changing or setting a password, erasing, and other
functions on supported drives.

Additionally, automatic unlocking by
[udev](https://www.freedesktop.org/software/systemd/man/latest/udev.html)
can be configured.

### Show encryption status

Show the encryption status of a device (i.e. whether it is locked,
unlocked, or unprotected).

```
sudo wd-security status /dev/sdX
```

where _sdX_ should be replaced by the name of the device file for your
device.

### Unlock password protected device

Unlock a password protected device and re-read the partition table:

```
sudo wd-security unlock --rescan /dev/sdX
```

where _sdX_ should be replaced by the name of the device file for your
device.

### Change/Set/Remove password protection

If the device is not currently protected by a password, then one may
be set.  In this case, a random 8-byte password salt will be generated,
the number of hash iterations to perform will be set based on timing of
the hash function, and a new Security Block will be written to the
device.

If the device is currently protected with a password, then it may be
changed, or removed.

```
sudo wd-security change-pw [--disable-protection] /dev/sdX
```

where _sdX_ should be replaced by the name of the device file for your
device.

### Secure erase

Securely erase a device by causing it to install a new Device Encryption
Key (DEK).

Every device should be erased at least once, to replace the possibly
insecure factory DEK[^1].

> [!CAUTION]
> All information on device will become lost and completely
> unrecoverable.

```
sudo wd-security erase /dev/sdX
```

where _sdX_ should be replaced by the name of the device file for your
device.

### Manual

See the [manual](doc/wd-security.adoc.in) for more detailed information
about sub-commands and supported switches.

## Automatic Unlocking

udev rules are provided in _00-wd-security.rules_ to support automatic
unlocking on device attach.  A _Key File_ corresponding to each device
that will be automatically unlocked must be prepared and placed into the
_/etc/keys_ directory.

See the [manual](doc/wd-security.adoc.in) for information about how to
create a _Key File_ to enable automatic unlocking.

## List attached Western Digital drives

The `wd-security-devices.sh` script can be used to list all attached
Western Digital drives along with the name of the _Key File_ that should
be created to enable automatic unlocking.

## References

@DanLukes' excellent documentation[^2] of the protocol has been
infinitely valuable.  Without his painstaking reverse engineering work,
this project would not have been possible.

[^1]: [got HW crypto?](https://eprint.iacr.org/2015/1002.pdf)
[^2]: [WD_Encryption_API.txt](https://github.com/KenMacD/wdpassport-utils/raw/refs/heads/master/WD_Encryption_API.txt)
