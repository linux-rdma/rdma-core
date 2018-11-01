#/usr/bin/env python
"""This script transforms the structs inside the kernel ABI headers into a define
of an anonymous struct.

eg
  struct abc {int foo;};
becomes
  #define _STRUCT_abc struct {int foo;};

This allows the exact same struct to be included in the provider wrapper struct:

struct abc_resp {
   struct ibv_abc ibv_resp;
   _STRUCT_abc;
};

Which duplicates the struct layout and naming we have historically used, but
sources the data directly from the kernel headers instead of manually copying."""
import re;
import functools;
import sys;

def in_struct(ln,FO,nesting=0):
    """Copy a top level structure over to the #define output, keeping track of
    nested structures."""
    if nesting == 0:
        if re.match(r"(}.*);",ln):
            FO.write(ln[:-1] + "\n\n");
            return find_struct;

    FO.write(ln + " \\\n");

    if ln == "struct {" or ln == "union {":
        return functools.partial(in_struct,nesting=nesting+1);

    if re.match(r"}.*;",ln):
        return functools.partial(in_struct,nesting=nesting-1);
    return functools.partial(in_struct,nesting=nesting);

def find_struct(ln,FO):
    """Look for the start of a top level structure"""
    if ln.startswith("struct ") or ln.startswith("union "):
        g = re.match(r"(struct|union)\s+(\S+)\s+{",ln);
        FO.write("#define _STRUCT_%s %s { \\\n"%(g.group(2),g.group(1)));
        return in_struct;
    return find_struct;

with open(sys.argv[1]) as FI:
    with open(sys.argv[2],"w") as FO:
        state = find_struct;
        for ln in FI:
            # Drop obvious comments
            ln = ln.strip();
            ln = re.sub(r"/\*.*\*/","",ln);
            ln = re.sub(r"//.*$","",ln);
            state = state(ln,FO);
