#!/usr/bin/env python
# Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
"""This tool is used to create installable versions of the static libraries in rdma-core.

This is complicated because rdma-core was not designed with static libraries
in mind and relies on the dynamic linker to hide a variety of internal
details.

The build uses several internal utility libraries across the providers and the
libraries. When building statically these libraries have to become inlined
into the various main libraries. This script figures out which static
libraries should include which internal libraries and inlines them
appropriately.

rdma-core is not careful to use globally unique names throughout all the
libraries and all the providers.  Normally the map file in the dynamic linker
will hide these external symbols. This script does something similar for static
linking by analyzing the libraries and map files then renaming internal
symbols with a globally unique prefix.

This is far too complicated to handle internally with cmake, so we have cmake
produce the nearly completed libraries, then process them here using bintuils,
and finally produce the final installation ready libraries."""

import collections
import subprocess
import argparse
import tempfile
import itertools
import sys
import os
import re

SymVer = collections.namedtuple(
    "SymVer", ["version", "prior_version", "globals", "locals"])

try:
    from tempfile import TemporaryDirectory
except ImportError:
    import shutil
    import tempfile

    # From /usr/lib/python3/dist-packages/setuptools/py31compat.py
    class TemporaryDirectory(object):
        def __init__(self):
            self.name = None
            self.name = tempfile.mkdtemp()

        def __enter__(self):
            return self.name

        def __exit__(self, exctype, excvalue, exctrace):
            try:
                shutil.rmtree(self.name, True)
            except OSError:
                pass
            self.name = None


try:
    from subprocess import check_output
except ImportError:
    # From /usr/lib/python2.7/subprocess.py
    def check_output(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError(
                'stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(
            stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd, output=output)
        return output

    subprocess.check_output = check_output


def parse_stanza(version, prior_version, lines):
    gbl = []
    local = []
    cur = None

    cur = 0
    for I in re.finditer(
            r"\s*(?:(global:)|(local:)(\s*\*\s*;)|(?:(\w+)\s*;))",
            lines,
            flags=re.DOTALL | re.MULTILINE):
        if I.group(1):  # global
            lst = gbl
        if I.group(2):  # local
            lst = local
        if I.group(3):  # wildcard
            lst.append("*")
            assert (cur is not gbl)
        if I.group(4):  # symbol name
            lst.append(I.group(4))

        assert cur == I.start()
        cur = I.end()
    assert cur == len(lines)

    return SymVer(version or "", prior_version or "", gbl, local)


def load_map(fn):
    """This is a lame regex based parser for GNU linker map files. It asserts if
    the map file is invalid. It returns a list of the global symbols"""
    with open(fn, "rt") as F:
        lines = F.read()
    p = re.compile(r"/\*.*?\*/", flags=re.DOTALL)
    lines = re.sub(p, "", lines)
    lines = lines.strip()

    # Extract each stanza
    res = []
    cur = 0
    for I in re.finditer(
            r"\s*(?:(\S+)\s+)?{(.*?)\s*}(\s*\S+)?\s*;",
            lines,
            flags=re.DOTALL | re.MULTILINE):
        assert cur == I.start()
        res.append(parse_stanza(I.group(1), I.group(3), I.group(2)))
        cur = I.end()
    assert cur == len(lines)

    return res


class Lib(object):
    def __init__(self, libfn, tmpdir):
        self.libfn = os.path.basename(libfn)
        self.objdir = os.path.join(tmpdir, self.libfn)
        self.final_objdir = os.path.join(tmpdir, "r-" + self.libfn)
        self.final_lib = os.path.join(os.path.dirname(libfn), "..", self.libfn)
        self.needs = set()
        self.needed = set()

        os.makedirs(self.objdir)
        os.makedirs(self.final_objdir)

        subprocess.check_call([args.ar, "x", libfn], cwd=self.objdir)
        self.objects = [I for I in os.listdir(self.objdir)]
        self.get_syms()

    def get_syms(self):
        """Read the definedsymbols from each object file"""
        self.syms = set()
        self.needed_syms = set()
        for I in self.objects:
            I = os.path.join(self.objdir, I)
            syms = subprocess.check_output([args.nm, "--defined-only", I])
            for ln in syms.decode().splitlines():
                ln = ln.split()
                if ln[1].isupper():
                    self.syms.add(ln[2])

            syms = subprocess.check_output([args.nm, "--undefined-only", I])
            for ln in syms.decode().splitlines():
                ln = ln.split()
                if ln[0].isupper():
                    if not ln[1].startswith("verbs_provider_"):
                        self.needed_syms.add(ln[1])

    def rename_syms(self, rename_fn):
        """Invoke objcopy on all the objects to rename their symbols"""
        for I in self.objects:
            subprocess.check_call([
                args.objcopy,
                "--redefine-syms=%s" % (rename_fn),
                os.path.join(self.objdir, I),
                os.path.join(self.final_objdir, I)
            ])

    def incorporate_internal(self, internal_libs):
        """If this library requires an internal library then we want to inline it into
        this lib when we reconstruct it."""
        for lib in self.needs.intersection(internal_libs):
            self.objects.extend(
                os.path.join(lib.final_objdir, I) for I in lib.objects)

    def finalize(self):
        """Write out the now modified library"""
        try:
            os.unlink(self.final_lib)
        except OSError:
            pass
        subprocess.check_call(
            [args.ar, "qsc", self.final_lib] +
            [os.path.join(self.final_objdir, I) for I in self.objects])


def compute_graph(libs):
    """Look at the symbols each library provides vs the symbols each library needs
    and organize the libraries into a graph."""
    for a, b in itertools.permutations(libs, 2):
        if not a.syms.isdisjoint(b.needed_syms):
            b.needs.add(a)
            a.needed.add(b)

    # Use transitivity to prune the needs list
    def prune(cur_lib, to_prune):
        for I in cur_lib.needed:
            I.needs.discard(to_prune)
            to_prune.needed.discard(I)
            prune(I, to_prune)

    for cur_lib in libs:
        for I in list(cur_lib.needed):
            prune(I, cur_lib)


parser = argparse.ArgumentParser(
    description='Generate static libraries for distribution')
parser.add_argument(
    "--map",
    dest="maps",
    action="append",
    help="List of map files defining all the public symbols",
    default=[])
parser.add_argument(
    "--lib", dest="libs", action="append", help="The input static libraries")
parser.add_argument(
    "--internal_lib",
    dest="internal_libs",
    action="append",
    help=
    "The internal static libraries, these will be merged into other libraries")
parser.add_argument(
    "--version", action="store", help="Package version number", required=True)
parser.add_argument("--ar", action="store", help="ar tool", required=True)
parser.add_argument("--nm", action="store", help="nm tool", required=True)
parser.add_argument(
    "--objcopy", action="store", help="objcopy tool", required=True)
args = parser.parse_args()

global_syms = set()
for fn in sorted(set(args.maps)):
    for I in load_map(fn):
        # Private symbols in libibverbs are also mangled for maximum safety.
        if "PRIVATE" not in I.version:
            global_syms.update(I.globals)

with TemporaryDirectory() as tmpdir:
    libs = set(Lib(fn, tmpdir) for fn in args.libs)
    internal_libs = set(Lib(fn, tmpdir) for fn in args.internal_libs)
    all_libs = libs | internal_libs

    all_syms = set()
    for I in all_libs:
        all_syms.update(I.syms)
    compute_graph(all_libs)

    # To support the ibv_static_providers() machinery these are made global
    # too, even though they are not in map files. We only want to expose them
    # for the static linking case.
    global_syms.add("ibv_static_providers")
    for I in all_syms:
        if I.startswith("verbs_provider_"):
            global_syms.add(I)

    # Generate a redefine file for objcopy that will sanitize the internal names
    prefix = re.sub(r"\W", "_", args.version)
    redefine_fn = os.path.join(tmpdir, "redefine")
    with open(redefine_fn, "wt") as F:
        for I in sorted(all_syms - global_syms):
            F.write("%s rdmacore%s_%s\n" % (I, prefix, I))

    for I in all_libs:
        I.rename_syms(redefine_fn)

    for I in libs:
        I.incorporate_internal(internal_libs)
        I.finalize()
