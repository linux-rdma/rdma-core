#!/usr/bin/env python
import os
import shutil
import subprocess
import sys
import hashlib
import re

def hash_rst_includes(incdir,txt):
    h = ""
    for fn in re.findall(br"^..\s+include::\s+(.*)$", txt, flags=re.MULTILINE):
        with open(os.path.join(incdir,fn.decode()),"rb") as F:
            h = h +  hashlib.sha1(F.read()).hexdigest();
    return h.encode();

def get_id(SRC):
    """Return a unique ID for the SRC file. For simplicity and robustness we just
    content hash it"""
    incdir = os.path.dirname(SRC)
    with open(SRC,"rb") as F:
        txt = F.read();
        if SRC.endswith(".rst"):
            txt = txt + hash_rst_includes(incdir,txt);
        return hashlib.sha1(txt).hexdigest();

def do_retrieve(src_root,SRC):
    """Retrieve the file from the prebuild cache and write it to DEST"""
    prebuilt = os.path.join(src_root,"buildlib","pandoc-prebuilt",get_id(SRC))
    sys.stdout.write(prebuilt);

def do_build_pandoc(build_root,pandoc,SRC,DEST):
    """Build the markdown into a man page with pandoc and then keep a copy of the
    output under build/pandoc-prebuilt"""
    try:
        subprocess.check_call([pandoc,"-s","-t","man",SRC,"-o",DEST]);
    except subprocess.CalledProcessError:
        sys.exit(100);
    shutil.copy(DEST,os.path.join(build_root,"pandoc-prebuilt",get_id(SRC)));

def do_build_rst2man(build_root,rst2man,SRC,DEST):
    """Build the markdown into a man page with pandoc and then keep a copy of the
    output under build/pandoc-prebuilt"""
    try:
        subprocess.check_call([rst2man,SRC,DEST]);
    except subprocess.CalledProcessError:
        sys.exit(100);
    shutil.copy(DEST,os.path.join(build_root,"pandoc-prebuilt",get_id(SRC)));

# We support python 2.6 so argparse is not available.
if len(sys.argv) == 4:
    assert(sys.argv[1] == "--retrieve");
    do_retrieve(sys.argv[2],sys.argv[3]);
elif len(sys.argv) == 7:
    assert(sys.argv[1] == "--build");
    if sys.argv[3] == "--pandoc":
        do_build_pandoc(sys.argv[2],sys.argv[4],sys.argv[5],sys.argv[6]);
    elif sys.argv[3] == "--rst":
        do_build_rst2man(sys.argv[2],sys.argv[4],sys.argv[5],sys.argv[6]);
    else:
        raise ValueError("Bad sys.argv[3]");
else:
    raise ValueError("Must provide --build or --retrieve");
