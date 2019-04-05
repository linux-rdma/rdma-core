import re
import sys

def global_ln(ln):
    g = re.match(r"^#define\s+(\S+)\s+CL_HTON(\d+)\((.*)\)",ln)
    if g:
        print("#define %s htobe%s(%s)"%(g.group(1),g.group(2),g.group(3)))
        return global_ln
    g = re.match(r"^#define\s+(\S+)\s+\(CL_HTON(\d+)\((.*)\)\)",ln)
    if g:
        print("#define %s htobe%s(%s)"%(g.group(1),g.group(2),g.group(3)))
        return global_ln
    g = re.match(r"^#define\s+(\S+)\s+(0x\w+)",ln)
    if g:
        print("#define %s %s"%(g.group(1),g.group(2)))
        return global_ln
    g = re.match(r"^#define\s+(\S+)\s+\((0x\w+)\)",ln)
    if g:
        print("#define %s %s"%(g.group(1),g.group(2)))
        return global_ln
    g = re.match(r"^#define\s+(\S+)\s+(\d+)",ln)
    if g:
        print("#define %s %s"%(g.group(1),g.group(2)))
        return global_ln
    g = re.match(r"^#define\s+(\S+)\s+\((\d+)\)",ln)
    if g:
        print("#define %s %s"%(g.group(1),g.group(2)))
        return global_ln

    g = re.match(r"^typedef\s+(union|struct)\s+_\S+\s+{",ln);
    if g:
        print("typedef %s {"%(g.group(1)));
        return in_struct;

    print(ln,file=FO);
    return global_ln

def in_struct(ln):
    g = re.match(r"^}\s+PACK_SUFFIX\s+(\S+);",ln);
    if g:
        print("} __attribute__((packed)) %s;"%(g.group(1)));
        return global_ln;
    g = re.match(r"^}\s+(\S+);",ln);
    if g:
        print("} %s;"%(g.group(1)));
        return global_ln;

    ln = ln.replace("PACK_SUFFIX","__attribute__((packed))");
    ln = ln.replace("ib_gid_prefix_t","__be64");
    ln = ln.replace("ib_net64_t","__be64");
    ln = ln.replace("ib_net32_t","__be32");
    ln = ln.replace("ib_net16_t","__be16");
    ln = ln.replace("boolean_t","bool");
    print(ln)
    return in_struct;

mode = global_ln
with open(sys.argv[1]) as FI, open(sys.argv[2],"wt") as FO:
    for ln in FI:
        ln = ln.rstrip();
        mode = mode(ln);
