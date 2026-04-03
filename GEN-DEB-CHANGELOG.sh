#!/bin/sh

# Generate a debian changelog from a git history
#
# A changelog entry is created for each tagged release.
# - the version string will be derived from the tag ref after stripping
#   leading non-numeric characters, e.g. tag 'v1.0-bb' or 'foo-1.0-bb'
#   will both produce version '1.0-bb'.
# - the body of the changelog entry will be the subject line of the
#   annotated tag, if any.
# - the maintainer name, email and date will be taken from the annotated
#   tag or alternatively commit object.
# - if HEAD is not tagged or if the working directory is dirty, then the
#   first (top-most) changelog entry will be marked UNRELEASED, the body
#   of the changelog entry will contain a short listing of the new
#   commits since the most recent tag, and the maintainer name and email
#   will be taken from the GIT_COMMITTER_IDENT git variable.
#
# Copyright (C) 2026  Brandon Casey

EXTRA_VERSION=${EXTRA_VERSION:-}

# <tag-pattern> should be a glob(7) pattern that matches the portion of
#               a tag after the "refs/tags/" prefix.
gen_deb_changelog()
{
	if [ $# -lt 3 ]; then
		echo 1>&2 'usage: gen-deb-changelog <tag-pattern> <package> <distribution> [<meta>...]'
		return 1
	fi

	local tag_pattern=$1; shift
	local package=$1; shift
	local distribution=$1; shift
	local meta=$*

	local limit=20

	local ver
	local sha
	local count
	local extra=
	local trailer=

	# Version string describing HEAD
	ver=`git describe --always --tags --match "$tag_pattern" --dirty 2>/dev/null` &&

	# sha1 of most recent tag
	sha=`git for-each-ref --count=1 --merged=HEAD --sort='-creatordate' --format='%(*objectname)' "refs/tags/$tag_pattern"` &&

	# If working directory is dirty or HEAD is ahead of most recent
	# tag, then emit an UNRELEASED changelog entry
	if [ "$ver" != "${ver%-dirty}" ] ||
	   [ "$sha" != "$(git rev-parse HEAD^0)" ]
	then
		ver=`echo "x$ver" | sed -e 's/^[^0-9]\{0,\}//'` &&
		count=`git rev-list --count --no-merges "$sha${sha:+..}HEAD"` &&
		if [ "$count" -gt "$limit" ]; then
			extra=" ($count commits)"
			trailer='    ...
'
		fi &&
		cat <<-EOF
		$package ($ver$EXTRA_VERSION) UNRELEASED; $meta

		  * Unreleased changes$extra
		`git log -n "$limit" --no-merges --pretty='    %s' "$sha${sha:+..}HEAD"`
		$trailer
		 -- `git var GIT_COMMITTER_IDENT | sed -e 's/[^>]*$//'`  `date -R`

		EOF
	fi &&

	# Iterate through each tag and emit a changelog entry
	git for-each-ref --merged=HEAD --sort='-creatordate' --format="
$package (XXltrim-alphaXX%(refname:short)$EXTRA_VERSION) $distribution; $meta

  * %(subject)

 -- %(creator)XXrtrim-unixXX  %(creatordate:rfc)" "refs/tags/$tag_pattern" |
	sed -e '1d' \
	    -e 's/XXltrim-alphaXX[^0-9]\{0,\}//' \
	    -e 's/ [0-9]\{1,\} [-+][0-9]\{4\}XXrtrim-unixXX//'
}

gen_deb_changelog "$@"
