#!/bin/sh

usage()
{
	echo "Usage: $0 [--spec]"
	exit 2
}

if [ "$1" = "--spec" ] ; then
	spec_format=1
fi

GIT_DIR=`git rev-parse --git-dir 2>/dev/null`

test -z "$GIT_DIR" && usage


export GIT_DIR
export GIT_PAGER=""
export PAGER=""


mkchlog()
{
	format=$1

	prev_tag=""

	for tag in `git tag -l '*'` ; do
		obj=`git cat-file tag $tag | awk '/^object /{print $2}'`
		base=`git merge-base $obj HEAD`
		if [ -z "$base" -o "$base" != $obj ] ; then
			continue
		fi
		all_vers="$prev_tag$tag $all_vers"
		prev_tag=$tag..
	done

	if [ -z "$prev_tag" ] ; then
		all_vers=HEAD
	else
		all_vers="${prev_tag}HEAD $all_vers"
	fi

	for ver in $all_vers ; do
		log_out=`git log $ver -- ./`
		if [ -z "$log_out" ] ; then
			continue
		fi
		ver_name=`echo $ver | sed -e 's/^.*\.\.//'`
		echo ""
		echo "** Version: $ver_name"
		echo ""
		git log --no-merges "${format}" $ver -- ./
		prev_t=$tag..
	done
}


if [ -z "$spec_format" ] ; then
	mkchlog --pretty=format:"%ad %an%n%H%n%n* %s%n" \
		| sed -e 's/^\* /\t* /'
else
	echo "%changelog"
	mkchlog --pretty=format:"- %ad %an: %s"
	echo ""
fi
