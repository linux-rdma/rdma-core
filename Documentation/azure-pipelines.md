# Azure Pipelines Continuous Integration

rdma-core uses Azure Pipelines to run a variety of compile tests on every pull
request. These tests are intented to run through a variety of distribution
configurations with the goal to have rdma-core build and work on a wide range
of distributions.

The system consists of several components:
 - An Azure Container Registry
 - The script buildlib/cbuild to produce the container images representing the
   test scenarios
 - The instructions in buildlib/azure-pipelines.yml and related support scripts
 - An Azure Pipelines account linked to the rdma-core GitHub
 - A GitHub Check

Things are arranged so that the cbuild script can run the same commands in the
same containers on the local docker system, it does not rely on any special or
unique capabilities of Azure Pipelines.

# The Containers

Containers are built with the cbuild script. Internally it generates a
Dockerfile and builds a docker container.

```sh
$ buildlib/cbuild build-images centos7
```

cbuild has definitions for a wide range of platforms that are interesting to test.

## Uploading Containers

Containers that are used by Azure Pipelines are prefixed with
ucfconsort.azurecr.io/rdma-core/ to indicate they are served from that docker
registry (which is implemented as a Azure Cotnainer Registry service).

Once built the container should be uploaded with:

```sh
# Needed onetime
$ az login

$ sudo az acr login --name ucfconsort
$ sudo docker push ucfconsort.azurecr.io/rdma-core/centos7:latest
```

The user will need to be authorized to access the private registry.

## Testing containers locally

cbuild has several modes for doing local testing on the container.

The fastest is to use 'cbuild make' as a replacement for Ninja. It will run
cmake and ninja commands inside the container, but using the local source
tree unmodified. This is useful to test and resolve compilation problems.

```sh
$ buildlib/cbuild make centos7
```

Using 'make --run-shell' will perform all container setup but instead of
running Ninja it will open a bash shell inside the same container
environment. This is useful to test and debug the container contents.

Package builds can be tested using 'cbuild pkg'. This automatically generates
a source .tar.gz and then runs rpmbuild/etc within the container. This is
useful for testing the package building scripts. Note that any changes must be
checked in or they will not be included.

package builds are some of the tests that Azure Pipelines runs.

# Azure Pipelines

The actions are controlled by the content of buildlib/azure-pipelines.yml. The
process is fairly straightforward and consists of both running distribution
package builds and a series of different compilers and analysis checks.

The compiler checks are run in a special 'azure-pipelines' container that has
several compilers, ARM64 cross compilation, and other things.

cbuild is able to run an emulation of the pipelines commands using
'buildlib/cbuild pkg azp'

## Azure Pipelines Security

Microsoft has a strange security model - by default they do not send any login
secrets to the VM if the VM is triggered from a GitHub Pull Request. This is
required as the VM runs code from the PR, and a hostile PR could ex-filtrate
the secret data.

However, since fetching the containers requires a security token it means PR
cannot get the container, and are basically entirely useless. The only option
Azure Pipeliens has is to inject *all* security tokens, including the GitHub
token, which is madness.

The compromise is that when a non-team member user proposes a Pull Request a
team member must reivew it and add "/azp run" to the comments to ack that the
PR content is not hostile.

See

https://developercommunity.visualstudio.com/content/idea/392281/granular-permissions-on-secrets-for-github-fork-pu.html
