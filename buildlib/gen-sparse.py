#!/usr/bin/env python3
# Copyright 2015-2017 Obsidian Research Corp.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
import argparse
import subprocess
import os
import collections
import re
import itertools

headers = {
    "bits/sysmacros.h",
    "endian.h",
    "netinet/in.h",
    "pthread.h",
    "stdatomic.h",
    "stdlib.h",
    "sys/socket.h",
    };

def norm_header(fn):
    for I in headers:
        flat = I.replace("/","-");
        if fn.endswith(flat):
            return I;
        if fn.endswith(flat + ".diff"):
            return I;
    return None;

def find_system_header(args,hdr):
    """/usr/include is not always where the include files are, particularly if we
    are running full multi-arch as the azure_pipeline container does. Get gcc
    to tell us where /usr/include is"""
    if "incpath" not in args:
        cpp = subprocess.check_output([args.cc, "-print-prog-name=cpp"],universal_newlines=True).strip()
        data = subprocess.check_output([cpp, "-v"],universal_newlines=True,stdin=subprocess.DEVNULL,
                                       stderr=subprocess.STDOUT)
        args.incpath = [];
        for incdir in re.finditer(r"^ (/\S+)$", data, re.MULTILINE):
            incdir = incdir.group(1)
            if "fixed" in incdir:
                continue;
            args.incpath.append(incdir)

    for incdir in args.incpath:
        fn = os.path.join(incdir,hdr)
        if os.path.exists(fn):
            return fn
    return None;

def get_buildlib_patches(dfn):
    """Within the buildlib directory we store patches for the glibc headers. Each
    patch is in a numbered sub directory that indicates the order to try, the
    number should match the glibc version used to make the diff."""
    ver_hdrs = [];
    all_hdrs = []
    for d,_,files in os.walk(dfn):
        for I in files:
            if d != dfn:
                bn = int(os.path.basename(d));
            else:
                bn = 0;

            if bn == 0:
                all_hdrs.append(os.path.join(d,I));
            else:
                ver_hdrs.append((bn,os.path.join(d,I)));
    ver_hdrs.sort(reverse=True);

    def add_to_dict(d,lst):
        for I in lst:
            nh = norm_header(I)
            assert nh not in d
            d[nh] = (I, find_system_header(args,nh))

    ret = []
    for k,g in itertools.groupby(ver_hdrs,key=lambda x:x[0]):
        dd = {}
        ret.append(dd)
        add_to_dict(dd,(I for _,I in g))
        add_to_dict(dd,all_hdrs)
    return ret;

def is_patch(fn):
    with open(fn) as F:
        return F.read(10).startswith("-- /");

def apply_patch(src,patch,dest):
    """Patch a single system header. The output goes into our include search path
    and takes precedence over the system version."""
    if src is None:
        return False

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
            print("Patch from %r failed"%(patch));
            return False;
    except subprocess.CalledProcessError:
        print("Patch from %r failed"%(patch));
        return False;
    return True;

def replace_headers(suite):
    # Local system does not have the reference system header, this suite is
    # not supported
    for fn,pfn in suite.items():
        if pfn[1] is None:
            return False;

    for fn,pfn in suite.items():
        if not apply_patch(pfn[1],pfn[0],os.path.join(args.INCLUDE,fn)):
            break;
    else:
        return True;

    for fn,_ in suite.items():
        try:
            os.unlink(os.path.join(args.INCLUDE,fn))
        except OSError:
            continue;
    return False;

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
                                   find_system_header(args,fn),
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
parser.add_argument("--cc",default="gcc",
                    help="System compiler to use to locate the default system headers");
parser.add_argument("--save",action="store_true",default=False,
                    help="Save mode will write the current content of the headers to buildlib as a diff.");
args = parser.parse_args();

if args.save:
    # Get the glibc version string
    ver = subprocess.check_output(["ldd","--version"]).decode()
    ver = ver.splitlines()[0].split(' ')[-1];
    ver = ver.partition(".")[-1];
    outdir = os.path.join(args.SRC,"buildlib","sparse-include",ver);
    if not os.path.isdir(outdir):
        os.makedirs(outdir);

    for I in headers:
        save(I,outdir);
else:
    failed = False;
    suites = get_buildlib_patches(os.path.join(args.SRC,"buildlib","sparse-include"));
    for I in suites:
        if replace_headers(I):
            break;
    else:
        raise ValueError("Patch applications failed");
