#!/usr/bin/env python
# Copyright 2015-2017 Obsidian Research Corp.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
import argparse
import subprocess
import os
import collections

headers = {
    "endian.h",
    "netinet/in.h",
    "pthread.h",
    "sys/socket.h",
    "stdatomic.h",
    };

def norm_header(fn):
    for I in headers:
        flat = I.replace("/","-");
        if fn.endswith(flat):
            return I;
        if fn.endswith(flat + ".diff"):
            return I;
    return None;

def get_buildlib_patches(dfn):
    """Within the buildlib directory we store patches for the glibc headers. Each
    patch is in a numbered sub directory that indicates the order to try, the
    number should match the glibc version used to make the diff."""
    res = [];
    for d,_,files in os.walk(dfn):
        for I in files:
            if d != dfn:
                bn = int(os.path.basename(d));
            else:
                bn = 0;

            res.append((bn,os.path.join(d,I)));
    res.sort(reverse=True);

    ret = collections.defaultdict(list);
    for _,I in res:
        ret[norm_header(I)].append(I);
    return ret;

def is_patch(fn):
    with open(fn) as F:
        return F.read(10).startswith("-- /");

def apply_patch(src,patch,dest):
    """Patch a single system header. The output goes into our include search path
    and takes precedence over the system version."""
    dfn = os.path.dirname(dest);
    if not os.path.isdir(dfn):
        os.makedirs(dfn);

    if not patch.endswith(".diff"):
        if not os.path.exists(dest):
            os.symlink(patch,dest);
        return True;

    try:
        if os.path.exists(dest + ".rej"):
            os.unlink(dest + ".rej");

        subprocess.check_output(["patch","-f","--follow-symlinks","-V","never","-i",patch,"-o",dest,src]);

        if os.path.exists(dest + ".rej"):
            print "Patch from %r failed"%(patch);
            return False;
    except subprocess.CalledProcessError:
        print "Patch from %r failed"%(patch);
        return False;
    return True;

def replace_header(fn):
    tries = 0;
    for pfn in patches[fn]:
        if apply_patch(os.path.join(args.REF,fn),
                       pfn,os.path.join(args.INCLUDE,fn)):
            return;
        tries = tries + 1;

    print "Unable to apply any patch to %r, tries %u"%(fn,tries);
    global failed;
    failed = True;

def save(fn,outdir):
    """Diff the header file in our include directory against the system header and
    store the diff into buildlib. This makes it fairly easy to maintain the
    replacement headers."""
    if os.path.islink(os.path.join(args.INCLUDE,fn)):
        return;

    flatfn = fn.replace("/","-") + ".diff";
    flatfn = os.path.join(outdir,flatfn);

    with open(flatfn,"wt") as F:
        try:
            subprocess.check_call(["diff","-u",
                                   os.path.join(args.REF,fn),
                                   os.path.join(args.INCLUDE,fn)],
                                  stdout=F);
        except subprocess.CalledProcessError as ex:
            if ex.returncode == 1:
                return;
            raise;

parser = argparse.ArgumentParser(description='Produce sparse shim header files')
parser.add_argument("--out",dest="INCLUDE",required=True,
                    help="Directory to write header files to");
parser.add_argument("--src",dest="SRC",required=True,
                    help="Top of the source tree");
parser.add_argument("--ref",dest="REF",default="/usr/include/",
                    help="System headers to manipulate");
parser.add_argument("--save",action="store_true",default=False,
                    help="Save mode will write the current content of the headers to buildlib as a diff.");
args = parser.parse_args();

if args.save:
    # Get the glibc version string
    ver = subprocess.check_output(["ldd","--version"]).splitlines()[0].split(' ')[-1];
    ver = ver.partition(".")[-1];
    outdir = os.path.join(args.SRC,"buildlib","sparse-include",ver);
    if not os.path.isdir(outdir):
        os.makedirs(outdir);

    for I in headers:
        save(I,outdir);
else:
    failed = False;
    patches = get_buildlib_patches(os.path.join(args.SRC,"buildlib","sparse-include"));
    for I in headers:
        replace_header(I);

    if failed:
        raise ValueError("Patch applications failed");
