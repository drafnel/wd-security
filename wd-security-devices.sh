#!/bin/sh

# List Western Digital external devices and the path under which the
# udev rule will check for a key-file.

WD_VENDOR_ID=1058

header_shown=
udevadm info --export-db \
	--subsystem-match=block \
	--attr-nomatch='partition=*' \
	--attr-match='removable=0' \
	--property-match=ID_USB_VENDOR_ID="$WD_VENDOR_ID" |
	sed -n -e 's/^M: \(.*\)$/\1/p' | sort |
	while read device; do
		ID_USB_MODEL=
		ID_USB_SERIAL_SHORT=
		eval `udevadm info --query=property \
			--property='ID_USB_MODEL,ID_USB_SERIAL_SHORT' \
			"/dev/$device"` &&
		{
		  test -n "$header_shown" ||
		  echo 'Device    Key-File (for udev rule)' && header_shown=1
		}
		echo "/dev/$device: /etc/keys/WD_${ID_USB_MODEL}_${ID_USB_SERIAL_SHORT}.key"
	done
