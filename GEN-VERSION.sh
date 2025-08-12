#!/bin/sh

VERSION_FILE='VERSION.h'

# This string will be expanded by git-archive.
VERSION='$Format:%(describe:tags=true)$'

DRYRUN='no'
if [ "$#" != '0' -a "$1" = '-n' ]; then
	DRYRUN='yes'
fi

if type 'git' >/dev/null 2>&1 && test -d ${GIT_DIR:-.git} -o -f .git; then
	VERSION=`git describe --tags --dirty 2>/dev/null`
fi

MAJOR=${VERSION#v}
MAJOR=${MAJOR%%.*}
MINOR=${VERSION#*.}

MAJOR=${MAJOR:-0}
MINOR=${MINOR:-0}

if [ "$DRYRUN" = 'yes' ]; then
	echo "$MAJOR.$MINOR"
	exit
fi

NEED_VERSION=yes
if test -r "$VERSION_FILE"; then
	old_major=`sed -n -e 's/^#define MAJOR \(.*\)/\1/p' "$VERSION_FILE"`
	old_minor=`sed -n -e 's/^#define MINOR \(.*\)/\1/p' "$VERSION_FILE"`
	if [ "$old_major" = "$MAJOR" -a "$old_minor" = "$MINOR" ]; then
		NEED_VERSION=no
	fi
fi

if [ "$NEED_VERSION" = yes ]; then
	cat <<-EOF >$VERSION_FILE &&
	#define MAJOR $MAJOR
	#define MINOR $MINOR
	EOF
	echo 1>&2 "$MAJOR.$MINOR"
fi
