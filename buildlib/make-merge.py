#!/usr/bin/env python
"""Merge git trees together preserving history and tags"""
import subprocess;
import os;
import collections;
import tempfile;
import shutil;

gits = [
    # "git://git.openfabrics.org/~iraweiny/libibmad.git"
    "git://git.openfabrics.org/~tnikolova/libnes/.git",
    "git://git.openfabrics.org/~swise/libcxgb3.git",
    "git://git.openfabrics.org/~swise/libcxgb4.git",
    "git://git.openfabrics.org/~halr/libibumad.git",
    "git://git.openfabrics.org/~yishaih/libmlx5.git",
    "git://git.openfabrics.org/~yishaih/libmlx4.git",
    "git://git.kernel.org/pub/scm/libs/infiniband/libmthca.git",
    # ehca is obsolete and only compiles on ppc anyhow
    #"git://git.openfabrics.org/~alexschm/libehca.git",
    "git://git.kernel.org/pub/scm/libs/infiniband/libibverbs.git",
    "git://git.openfabrics.org/~tnikolova/libi40iw/.git",
    "git://git.openfabrics.org/~shefty/libibcm.git",
    "git://git.openfabrics.org/~emulex/libocrdma.git",
    "https://github.com/ofiwg/librdmacm.git",
    "https://github.com/01org/opa-libhfi1verbs.git",
    "https://github.com/01org/libipathverbs.git",
    "https://github.com/SoftRoCE/librxe-dev.git",

    "git://git.openfabrics.org/~bvanassche/srptools.git",
    "git://git.openfabrics.org/~tnikolova/libiwpm",
    "https://github.com/ofiwg/ibacm.git"
];

def get_git_info(giturl):
    name = giturl.split('/')[-1].partition('.')[0];
    if not name:
        name = giturl.split('/')[-2].partition('.')[0];

    branch = "origin/master"
    if name == "opa-libhfi1verbs":
        name = "libhfi1verbs";
    if name == "librxe-dev":
        branch = "origin/librxe-1.0.0";
        name = "librxe";
    if name == "libiwpm":
        name = "iwpmd";
    if name == "srptools":
	name = "srp_daemon";
    return name,branch;

def clone(to,giturl):
    name,branch = get_git_info(giturl);
    if not os.path.exists(to):
        subprocess.check_call(["git","clone",giturl,to]);
    else:
        subprocess.call(["git","-C",to,"remote","remove","origin"]);
        subprocess.check_call(["git","-C",to,"remote","add","origin",giturl]);
        subprocess.check_call(["git","-C",to,"fetch","origin"]);
        subprocess.check_call(["git","-C",to,"reset","--hard",branch]);

def load_gits():
    odata = collections.namedtuple("odata","path head url name");
    originals = {};
    for I in gits:
        name,branch = get_git_info(I);

        path = os.path.realpath(os.path.join("original",name));
        clone(path,I);
        head = subprocess.check_output(["git","-C",path,"rev-parse",branch]);
        head = head.strip();
        originals[name] = odata(path=path,head=head,url=I,name=name);
    return originals;

def create_repo():
    if os.path.exists("combined"):
        shutil.rmtree("combined");
    os.mkdir("combined");
    os.chdir("combined");
    subprocess.check_call(["git","init"]);
    with open(".git/objects/info/alternates","wt") as F:
        for k,v in originals.iteritems():
            print >> F,os.path.join(v.path,".git","objects");

def read_tags(odata):
    try:
        lst = subprocess.check_output(["git","-C",odata.path,"show-ref","--tags"]).splitlines();
    except subprocess.CalledProcessError:
        # Weird, git returns an error if there are no tags
        return {};
    tags = {}
    for I in subprocess.check_output(["git","-C",odata.path,"show-ref","--tags"]).splitlines():
        blob,name = I.split(' ');
        assert name.startswith("refs/tags/");

        # Cannoize subproject tag names
        name = name[10:];
        if not name.startswith(odata.name):
            if name.startswith('v'):
                name = name[1:]
            name = "%s-%s"%(odata.name,name);
        tags[name] = blob;
    return tags;

def populate():
    parents = [];
    for k,v in sorted(originals.iteritems()):
        # Each repo gets a rename stub commit, this makes 'git log --follow' work much better
        subprocess.check_call(["git","read-tree","--prefix",k,v.head]);
        tree = subprocess.check_output(["git","write-tree"]).strip();
        os.unlink(".git/index");

        with tempfile.NamedTemporaryFile() as F:
            print >> F,"Rename %s"%(k);
            print >> F;
            print >> F,"Move all files to %s/"%(k);
            print >> F;
            print >> F,"Signed-off-by: Jason Gunthorpe <jgunthorpe@obsidianresearch.com>";
            F.flush();
            commit = subprocess.check_output(["git","commit-tree","-F",F.name,tree,"-p",v.head]).strip();
        parents.append("-p");
        parents.append(commit);

    for k,v in sorted(originals.iteritems()):
        subprocess.check_call(["git","read-tree","--prefix",k,v.head]);

        for name,blob in read_tags(v).iteritems():
            subprocess.check_call(["git","tag",name,blob]);
    return parents;

def commit():
    tree = subprocess.check_output(["git","write-tree"]).strip();

    with tempfile.NamedTemporaryFile() as F:
        print >> F,"Initial commit";
        print >> F;
        print >> F,"This was built from the original upstream repositories:";
        for k,v in sorted(originals.iteritems()):
            print >> F,"  %s %s %s"%(k,v.url,v.head);
        print >> F;
        print >> F,"Signed-off-by: Jason Gunthorpe <jgunthorpe@obsidianresearch.com>";
        F.flush();
        commit = subprocess.check_output(["git","commit-tree","-F",F.name,tree] + parents).strip();
        subprocess.check_call(["git","reset","--hard",commit]);

originals = load_gits();
create_repo();
parents = populate();
commit();
