# Stable Branch Release


## General

Current Maintainer: Nicolas Morey-Chaisemartin <NMoreyChaisemartin@suse.de>

Upstream rdma-core is considered stable after each mainline release.
Branched stable releases, off a mainline release, are on as-needed basis and limited to bug fixes only.

All bug fixes are to be backported from mainline and applied by stable branch maintainer.

Branched stable releases will append an additional release number (e.g. 15.1) and will ensure that Azure Pipelines CI reports a successful build.

Regular stable releases will be generated at the same time as mainline releases.
Additional stable releases can be generated if the need arise (Needed by distributions or OFED).

## Patch Rules

 * It must be obviously correct and tested.
 * It cannot be bigger than 100 lines, with context.
 * It must fix only one thing.
 * It must fix a real bug that bothers people (not a, "This could be a problem..." type thing).
 * ABI must NOT be changed by the fix.

## Submitting to the stable branch

Submissions to the stable branch follow the same process as [kernel-stable](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/stable-kernel-rules.rst).

### Option 1

Patches sent to master should add the tag:

   `Cc: stable@linux-rdma.org`

in the sign-off area. Once the patch is merged, it will be applied to the stable tree
without anything else needing to be done by the author or subsystem maintainer.

If the patch should be applied to more than one release, add the info version as such:

   `Cc: stable@linux-rdma.org # v15.1 v14`


### Option 2

After the patch has been merged to master, send an email to
stable@linux-rdma.org containing the subject of the patch, the commit ID,
why you think it should be applied, and what rdma-core version you wish it to
be applied to.

### Option 3

Send the patch, after verifying that it follows the above rules, to stable@linux-rdma.org.
You must note the upstream commit ID in the changelog of your submission,
 as well as the rdma-core version you wish it to be applied to.

Option 1 is strongly preferred, is the easiest and most common.
Option 2 and Option 3 are more useful if the patch isnâ€™t deemed worthy at the time it is applied to a public git tree (for instance, because it deserves more regression testing first).
Option 3 is especially useful if the patch needs some special handling to apply to an older version.

Note that for Option 3, if the patch deviates from the original upstream patch (for example because it had to be backported) this must be very clearly documented and justified in the patch description.

## Versioning

See versioning.md for setting package version on a stable branch.


## Creating a stable branch

Stable branch should be created from a release tag of the master branch.
The first thing to do on a master branch is to commit the mainstream release ABI infos
so that latters patches/fixes can be checked against this reference.

To do that, the creator of the branch should run
```
./buildlib/cbuild build-images azp
mkdir ABI
touch ABI/.gitignore
git add ABI/.gitignore
git commit -m "ABI Files"
./buildlib/cbuild pkg azp
git add ABI/*
git commit --amend
```

'cbuild pkg azp' will fail as the ABI verification step files, but it will
produce the ABI reference files.

Note that the ABI directory must NOT be committed at any point in the master branch.
