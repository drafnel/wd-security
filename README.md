
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

This software supports unlocking, changing or setting a password,
erasing, and other functions on supported drives, allowing an encrypted
drive to be shared between Windows, Mac, and Linux.

## Listing attached Western Digital drives

On Linux, udev can be used to list all Western Digital drives using the
`udevadm` utility by searching for USB devices with Western Digital's
Vendor ID "1058".

```
$ udevadm info --export-db \
               --subsystem-match=block \
               --attr-nomatch='partition=*' \
               --attr-match='removable=0' \
               --property-match=ID_USB_VENDOR_ID="1058"
```

The `wd-security-devices.sh` script will print the results in a format
that is much easier to read along with the name of the Key-File that
should be used, if auto-unlocking is desired.

##  wd-security Operations

### Getting help

Use the `--help` switch or the `help` sub-command to display a brief
overview of supported operations.

```
$ wd-security --help
usage: wd-security [--help] status|unlock|change-pw|erase ...

Manage password protection of external drives supported by
the proprietary WD Security software.

Sub-commands:
 status          show encryption status
 unlock          unlock device
 change-pw       change or set password
 erase           erase device
 handy-store     show/manipulate Handy Store
 version         version information
 help            this text
```

The name of a sub-command may also be supplied to the `--help` switch
or `help` sub-command to see more detailed information about the
command.

### Showing device encryption status

By default, shows the encryption status of the device (i.e. whether it
is locked, unlocked, or unprotected).

```
$ wd-security status /dev/sdX
```

If the `--is-locked` switch is passed, then the normal output will be
suppressed and the command will exit with a status of zero to indicate
that the device is supported and is currently locked, and will exit
with a non-zero status otherwise.

### Unlock password protected device

Unlock a password protected device.

```
$ wd-security unlock /dev/sdX
```

If a password is not supplied, then it will be prompted for.

If the `--rescan` switch is specified, then the Linux kernel will be
notified that it should reread the partition table for the device.

### Change/Set/Remove password protection

If the device is not currently protected with a password, then one may
be set.  If a salt and/or iterations is not specified (which is the
normal scenario), then a random salt will be generated and the number
of hash iterations to perform will be set based on timing of the hash
function.

If the device is currently protected with a password, then it may be
changed.

Lastly, if the device is currently protected with a password, it may be
removed so that the device is no longer protected by a password by
specifying the `--disable-protection` switch (or just '--disable').
Additionally, the Security Block of the Handy Store will be cleared.

```
$ wd-security change-pw [--disable-protection] /dev/sdX
```

If the old and/or new passwords (as appropriate) are not specified, then
they will be prompted for.

### Secure erase

The `erase` sub-command may be used to securely erase a device by
causing the device to install a new Device Encryption Key (DEK).

It is recommended to erase the device at least once to clear the,
possibly insecure, factory DEK[^1].

> [!CAUTION]
> Once this is done, all information that existed on the device will
> become lost and completely unrecoverable.

```
$ wd-security erase /dev/sdX
```

### Show Handy Store

Modern WD devices support a special area on the harddrive where
encryption parameters and user metadata may be stored, e.g. the
password salt, iterations, password hint, and drive label.  This area is
called the Handy Store.

Use the `handy-store` sub-command to display or modify it.

```
$ wd-security handy-store /dev/sdX
```

## Auto-unlocking on device attach

The encryption password may be placed into a key-file and used by a
udev rule to automatically unlock a locked device when it is attached.

The udev rule file `00-wd-security.rules` should be placed in one of
the directories that udev searches for rules (e.g. /etc/udev/rules.d).
Once this is done, when a Western Digital device is attached, udev will
perform the following operations:

1. check for the existence of a key-file for the device
2. check whether the device is locked
3. attempt to use the key-file to unlock the device
4. notify the kernel to reread the partition table of the device

### Create a key-file

Key files should be placed in /etc/keys and should be given a name that
follows the following format:

> WD_${ID_USB_MODEL}_${ID_USB_SERIAL_SHORT}.key

The ID_USB_MODEL and ID_USB_SERIAL_SHORT properties may be found in the
udev database, but with all spaces and slashes, etc. converted to
underscores.  The `wd-security-devices.sh` script will show the name of
the key-file that should be used with each device.

Once the name of the key-file is determined, the password in UTF-16LE
encoding should be written to the file.  This can be done using the
`iconv` utility to convert the UTF-8 encoded password into UTF-16LE:

```
$ echo -n 'my-secret-password' >utf8-password.txt
$ iconv -f UTF-8 -t UTF-16LE -o name-of-keyfile.key utf8-password.txt
$ rm utf8-password.txt
```

### Place key-file in /etc/keys

Once the key-file has been created, first test that it can successfully
unlock the device by specifying the key-file to the `unlock`
sub-command:

```
$ wd-security unlock --key-file /path/to/my/keyfile.key /dev/sdX
```

Once the key-file has been confirmed to work, place it in /etc/keys so
it can be found by the udev rule:

```
$ cp WD_mode_serial.key /etc/keys
$ chmod 400 /etc/keys/WD_mode_serial.key
```

### Unplug/Plug device in, confirm that it is unlocked automatically

Monitor the system log for udev errors.

## ISSUES

### Proprietary WD Security software

1. The default salt and iteration count are "WDC." and 1000.  The
proprietary WD Security software *always* uses these values when
creating a password.  Not only is 1000 a pathetically low iteration
count for even ancient CPUs, but using fixed values completely negates
the value of having a salt and performing multiple rounds of hashing.
Fixed values means that it is possible to pre-generate a rainbow table
of all possible (or likely) passwords and use it to instantly unlock any
drive that has been configured with the proprietary WD Security software
on Windows or MacOS.  When `wd-security` enables password protection on
a device it will generate a new salt randomly and calculate an
appropriate iteration count based on timing the hash operation.

2. When the proprietary WD Security software is used to *change* the
encryption password, it will do so using the existing salt and iteration
count configured on the drive, which is the correct behavior, but after
changing the password it will then overwrite the existing Security Block
with the *default* salt and iteration count, making it impossible to unlock
the drive again unless the old salt and iteration count are known and can
be restored.
   - For this reason, it is a good idea to backup the salt and iteration
     count.  If these are known, then access to the drive can be
     restored by overriding the salt and iteration count on the
     command-line when unlocking the drive with the new password and
     optionally restoring the security block.
     
### wdpassport-utils.py

This is a Python utility designed for much the same purpose as this
project, but it does not handle the password salt correctly.

When this utility sets the password on a device that does not have an
existing Security Block, it will create one by generating an 8-byte salt
from ASCII characters and write it to the Security Block.  But when it
attempts to use the salt (any salt, whether it wrote it or not), it will
drop every other byte, resulting in a 4-byte salt which it will then
convert to UTF-16 (platform endianness).

This has 2 consequences:

1. This procedure will _happen_ to work correctly with any salt that is
composed entirely of UTF-16LE encoded ASCII characters, e.g. the default
salt that the proprietary WD Security software uses: "WDC.", but not with
any other salt.
2. The proprietary WD Security software will not be able to unlock any
device that has a Security Block written by this utility.

Luckily this utility populates the password hint field with a specific string
that can be used to identify Security Blocks that have been written by it.
By default, `wd-security` will detect this string and enable workarounds
to allow unlocking drives configured by the wdpassport-utils.py utility.

## REFERENCES

@DanLukes' excellent documentation[^2] of the protocol has been
infinitely valuable.  Without his painstaking reverse engineering work,
this project would not have been possible.

[^1]: [got HW crypto?](https://eprint.iacr.org/2015/1002.pdf)
[^2]: [WD_Encryption_API.txt](https://github.com/KenMacD/wdpassport-utils/raw/refs/heads/master/WD_Encryption_API.txt)
