# Contributing to rdma-core

rdma-core is a userspace project for a Linux kernel interface and follows many
of the same expectations as contributing to the Linux kernel:

 - One change per patch

   Carefully describe your change in the commit message and break up work into
   appropriate reviewable commits.

   Refer to [Linux Kernel Submitting Patches](https://github.com/torvalds/linux/blob/master/Documentation/process/submitting-patches.rst)
   for general information.

 - Developer Certificate of Origin 'Signed-off-by' lines

   Include a Signed-off-by line to indicate your submission is suitable
   licensed and you have the legal authority to make this submission
   and accept the [DCO](#developers-certificate-of-origin-11)

 - Broadly follow the [Linux Kernel coding style](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-style.rst)

As in the Linux Kernel, commits that are fixing bugs should be marked with a
Fixes: line to help backporting.

Test your change locally before submitting it, you can use 'buildlib/cbuild'
to run the CI process locally and ensure your code meets the mechanical
expectations before sending the PR.

# Using GitHub

Changes to rdma-core should be delivered via [GitHub Pull Request](https://docs.github.com/en/github/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests)
to the [rdma-core](https://github.com/linux-rdma/rdma-core) project.

Each pull request should have a descriptive title and "cover letter" summary
indicating what commits are present.

A brief summary of the required steps:

- Create a github account for yourself
- [Clone](https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository-from-github/cloning-a-repository)
  the [rdma-core](https://github.com/linux-rdma/rdma-core) project in GitHub
- Setup a local clone of your repository using 'git clone'.
- Ensure your local branch is updated to the tip of rdma-core
- Make your change. Form the commits and ensure they are correct
- Push to your local git repository to your GitHub on a dedicated branch.
- Using the GitHub GUI make a Pull Request from the dedicated branch to
  rdma-core

## Making Revisions

If changes are required they should be integrated into the commits and the
pull request updated via force push to your branch. As a policy rdma-core
wishes to have clean commit objects. As a courtesy to others describe the
changes you made in a Pull Request comment and consider to include a
before/after diff in that note.

Do not close/open additional pull requests for the same topic.

## Continuous Integration

rdma-core performs a matrix of compile tests on each Pull Request. This is to
ensure the project continues to be buildable on the wide range of supported
distributions and compilers. These tests include some "static analysis" passes
that are designed to weed out bugs.

Serious errors will result in a red X in the PR and will need to be corrected.
Less serious errors, including checkpatch related, will show up with a green
check but it is necessary to check the details to see that everything is
appropriate. checkpatch is an informative too, not all of its feedback is
appropriate to fix.

A build similar to AZP can be run locally using docker and the
'buildlib/cbuild' script.

```sh
$ buildlib/cbuild build-images azp
$ buildlib/cbuild pkg azp
```

## Coordinating with Kernel Changes

Some changes consume a new uAPI that needs to be added to the kernel. Adding a
new rdma uAPI requires kernel and user changes that must be presented together
for review.

- Prepare the kernel patches and rdma-core patches together. Test everything

- Send the rdma-core patches as a PR to GitHub and possibly the mailing list

- Send the kernel pathces to linux-rdma@vger.kernel.org. Refer to the matching
  GitHub PR in the cover letter by URL

- The GitHub PR will be marked with a 'needs-kernel-patch' tag and will not
  advance until the kernel component is merged.

Keeping the kernel include/uapi header files in sync requires some special
actions. The first commit in the series should synchronize the kernel headers
copies in rdma-core with the proposed new kernel-headers that this change
requires. This commit is created with the script:

```sh
$ kernel-headers/update ~/linux.git HEAD --not-final
```

It will generate a new commit in the rdma-core.git that properly copies the
kernel headers from a kernel git tree. The --not-final should be used until
official, final, commits are available in the canonical [git
tree](http://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git)

This will allow the CI to run and the patches to be reviewed.

Once the kernel commits are applied a final git rebase should be used to
revise the kernel-headers commit:

```sh
$ kernel-headers/update ~/linux.git <commit ID> --amend
```

The updated commits should be force pushed to GitHub.

Newer kernels should always work with older rdma-core and newer rdma-core
should always work with older kernels. Changes forcing the simultaneous
upgrade of the kernel and rdma-core are forbidden.

# Participating in the Mailing List

Patches of general interest should be sent to the mailing list
linux-rdma@vger.kernel.org for detailed discussion. In particular patches that
modify any of the ELF versioned symbols or external programming API should be
sent to the mailing list.

While all patches must have a GitHub Pull Request created, minor patches can
skip the mailing list process.

# Making a new library API

All new library APIs that can be called externally from rdma-core require a
man page describe the API and must be sent to the mailing list for review.
This includes device specific "dv" APIs.

Breaking the ABI of any exported symbol is forbidden.

# Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

        (a) The contribution was created in whole or in part by me and I
            have the right to submit it under the open source license
            indicated in the file; or

        (b) The contribution is based upon previous work that, to the best
            of my knowledge, is covered under an appropriate open source
            license and I have the right under that license to submit that
            work with modifications, whether created in whole or in part
            by me, under the same open source license (unless I am
            permitted to submit under a different license), as indicated
            in the file; or

        (c) The contribution was provided directly to me by some other
            person who certified (a), (b) or (c) and I have not modified
            it.

        (d) I understand and agree that this project and the contribution
            are public and that a record of the contribution (including all
            personal information I submit with it, including my sign-off) is
            maintained indefinitely and may be redistributed consistent with
            this project or the open source license(s) involved.

then you just add a line saying:

        Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)
This will be done for you automatically if you use ``git commit -s``.
Reverts should also include "Signed-off-by". ``git revert -s`` does that
for you.
