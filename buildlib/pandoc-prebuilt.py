#!/usr/bin/env python
import os
import shutil
import subprocess
import sys
import hashlib

def get_id(SRC):
    """Return a unique ID for the SRC file. For simplicity and robustness we just
    content hash it"""
    with open(SRC,"rb") as F:
        return hashlib.sha1(F.read()).hexdigest();

def do_retrieve(src_root,SRC):
    """Retrieve the file from the prebuild cache and write it to DEST"""
    prebuilt = os.path.join(src_root,"buildlib","pandoc-prebuilt",get_id(SRC))
    sys.stdout.write(prebuilt);

def do_build(build_root,pandoc,SRC,DEST):
    """Build the markdown into a man page with pandoc and then keep a copy of the
    output under build/pandoc-prebuilt"""
    try:
        subprocess.check_call([pandoc,"-s","-t","man",SRC,"-o",DEST]);
    except subprocess.CalledProcessError:
        sys.exit(100);
    shutil.copy(DEST,os.path.join(build_root,"pandoc-prebuilt",get_id(SRC)));

# We support python 2.6 so argparse is not available.
if len(sys.argv) == 4:
    assert(sys.argv[1] == "--retrieve");
    do_retrieve(sys.argv[2],sys.argv[3]);
elif len(sys.argv) == 7:
    assert(sys.argv[1] == "--build");
    assert(sys.argv[3] == "--pandoc");
    do_build(sys.argv[2],sys.argv[4],sys.argv[5],sys.argv[6]);
else:
    raise ValueError("Must provide --build or --retrieve");
