echo "Creating a change log entry..."
echo "Enter changelog line:"
read resp
date_code=`date +"%a %b %d %Y"`
user_name=`git config user.name`
email=`git config user.email`

if [[ ! -e .git ]]; then
	echo "Must be run from git repo"
	exit 1
fi

VERSION=`git describe --tags --abbrev=0 --match='v*' | sed -e 's/^v//' -e 's/-/_/'`
RELEASE=`git describe --tags --long --match='v*' | sed -e 's/v[0-9.]*-\([0-9]*\)/\1/' | sed 's/-g.*$//'`

echo "* $date_code $user_name <$email> $VERSION-$RELEASE" >> fedora_changelog.txt
echo "- $resp" >> fedora_changelog.txt

