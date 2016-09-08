#!/usr/bin/env python
"""Compare the results of auto* vs cmake builds"""
import subprocess;
import os;
import sys;
import inspect;
import argparse;
import shutil;
import re;
import pickle;
import collections;
import json;

CompileArgs = collections.namedtuple("CompileArgs","args cwd");

def sources():
    """List of all original source directories"""
    for I in os.listdir(git_root):
        if I.startswith("lib") or I == "iwpmd" or I == "srp_daemon" or I == "ibacm":
            yield os.path.join(git_root,I);

def cmd_prepare_auto(args):
    """Run autotools in the source tree, do this first"""
    for I in sources():
        print I
        if os.path.exists(os.path.join(I,"autogen.sh")):
            subprocess.check_call(["/bin/bash","./autogen.sh"],cwd=I);
        else:
            # Sigh, some do not include the script
            subprocess.check_call(["/bin/bash",os.path.join(git_root,"libmthca","autogen.sh")],cwd=I);

def get_make_cmds(bdir):
    for I in subprocess.check_output(["make","-n"],cwd=bdir).splitlines():
        yield I;

    # libumad has some tests
    try:
        out = subprocess.check_output(["make","-n","check-TESTS"],cwd=bdir);
    except subprocess.CalledProcessError:
        pass
    else:
        for I in out.splitlines():
            yield I;

def canonize_args(cmd,src,bdir):
    """Extract only the compiler arguments for a C compile and remove unnecessary stuff"""
    s = re.match(r"^.*libtool.*--tag=CC.* gcc (.*)$",cmd);
    if s is not None:
        cmd = s.group(1);
    s = re.match(r"^gcc\s+(.*)$",cmd);
    if s is not None:
        cmd = s.group(1);
    s = re.match(r"^/usr/bin/cc\s+(.*)$",cmd);
    if s is not None:
        cmd = s.group(1);
    s = re.match(r"(.*) &&.*$",cmd);
    if s is not None:
        cmd = s.group(1);
    cmd = re.sub(src,'',cmd);
    cmd = re.sub(r"-o\s+\S+",'',cmd);
    cmd = re.sub(r"-MF\s+\S+",'',cmd);
    cmd = re.sub(r"-MT\s+\S+",'',cmd);
    cmd = re.sub("-MD",'',cmd);
    cmd = re.sub("-MP",'',cmd);
    cmd = re.sub("-c",'',cmd);
    cmd = re.sub(r"\\",'',cmd);
    res = set(cmd.split(' '));
    res.discard('')
    return CompileArgs(args=res,cwd=bdir);

def extract_make_cmds(sdir,bdir):
    """Process the output from make to figure out the gcc commands used"""
    cmds = {};
    for I in get_make_cmds(bdir):
        # libtool madness
        I = re.sub(r"`test -f '.+' \|\| echo '(%s/.+/)'`"%(git_root),r"\1",I);
        I = re.sub(r"^echo.*CC.*;","",I);

        # libtool format
        m = re.match(r".*libtool.* --tag=CC .*(%s/.*\.c).*$"%(git_root),I);
        if m is None:
            # gcc format
            m = re.match(r"^gcc.* -c .*(%s/.*\.c).*$"%(git_root),I);
        if m:
            src = os.path.join(sdir,m.group(1));
            I = canonize_args(I,src,bdir);
            if src in cmds:
                assert cmds[src] == I;
            cmds[src] = I;
            continue;
    return cmds;

def cmd_get_auto_commands(args):
    """Figure out the gcc commands being run by auto* and write out a pickle file
    with the data."""
    # Union all the includes so we use our own headers
    includes = set()
    for I in sources():
        inc = os.path.join(I,"include")
        if os.path.exists(inc):
            includes.add(inc);

    for I in sources():
        proj = os.path.basename(I);
        bdir = os.path.join(git_root,"abuild",proj);

        if os.path.exists(bdir):
            shutil.rmtree(bdir);
        os.makedirs(bdir);

        env = os.environ.copy();
        env["CPPFLAGS"] = " ".join("-I%s"%(J) for J in includes);
        print I
        subprocess.check_call([os.path.join(I,"configure")],cwd=bdir,env=env);

    cmd_get_auto_commands2(args);

def cmd_get_auto_commands2(args):
    """Substep of get_auto_commands, assume configure has been run and just process make output"""
    all_cmds = {};
    for I in sources():
        proj = os.path.basename(I);
        bdir = os.path.join(git_root,"abuild",proj);

        cmds = extract_make_cmds(I,bdir);
        assert set(all_cmds.keys()).isdisjoint(set(cmds.keys()));
        all_cmds.update(cmds);

    all_c = set();
    for I in subprocess.check_output(["git","ls-files"],cwd=git_root).splitlines():
        if I.endswith(".c"):
            all_c.add(os.path.join(git_root,I));
    assert set(all_cmds.keys()).issubset(all_c);
    print "Missing .c files: %r"%(all_c - set(all_cmds.keys()));

    fn = os.path.join(git_root,"abuild","arguments.pickle");
    with open(fn,"wt") as F:
        pickle.dump(all_cmds,F);
    print "Saved",fn;

def do_cpp(src,ofn,cmd):
    ofnd = os.path.dirname(ofn);
    if not os.path.exists(ofnd):
        os.makedirs(ofnd);

    # These switches impact what the glibc headers do, just force them
    args = cmd.args - {"-DNDEBUG"}
    args.update(["-O2","-DNVALGRIND","-DINCLUDE_VALGRIND=1","--std=gnu99"]);

    # Cannonize include paths to absolute paths
    for I in list(args):
        if I.startswith("-I"):
            n = "-I" + os.path.realpath(os.path.join(cmd.cwd,I[2:]));
            args.remove(I);
            args.add(n);

    args = ["gcc","-E","-o",ofn+".tmp",src] + [I for I in sorted(args)]

    print cmd.cwd,args
    sys.stdout.flush();
    subprocess.check_call(args,cwd=cmd.cwd);

    # Translate the cpp output to cannonize all the path names
    with open(ofn+".tmp") as FI, open(ofn,"wt") as FO:
        for I in FI.readlines():
            # Irrelevant differences
            if (re.match(r'^#.*command-line',I) is not None or
                re.match(r'^#.*built-in',I) is not None or
                re.match(r'^#.*"%s/*"'%(cmd.cwd),I) is not None or
                re.match(r'^#.*".*/config.h"',I) is not None):
                continue;

            m = re.match(r'^# \d+ "(.*)"',I);
            if m is not None:
                I = I.replace(m.group(1),os.path.realpath(
                    os.path.join(cmd.cwd,m.group(1))));
            m = re.search(r'"(%s/[^"]+)"'%(git_root),I);
            if m is not None:
                I = I.replace(m.group(1),os.path.realpath(
                    os.path.join(cmd.cwd,m.group(1))));
            FO.write(I);
    os.unlink(ofn+".tmp");

def cmd_run_cpp_auto(args):
    """Generate the cpp output auto*, do this after get-auto-commands"""
    fn = os.path.join(git_root,"abuild","arguments.pickle");
    with open(fn) as F:
        all_cmds = pickle.load(F);

    # We need a bit of help for the rdma_user_rxe.h file, just hack it..
    inc = os.path.join(git_root,"libibverbs/include/rdma");
    if not os.path.isdir(inc):
        os.makedirs(inc);
    inc = os.path.join(inc,"rdma_user_rxe.h");
    if not os.path.exists(inc):
        os.symlink("../../../buildlib/fixup-include/rdma-rdma_user_rxe.h",inc);

    bdir = os.path.join(git_root,"abuild","cpp");
    if os.path.exists(bdir):
        shutil.rmtree(bdir);
    for k,v in all_cmds.iteritems():
        assert k.startswith(git_root);
        ofn = os.path.join(bdir,k[len(git_root)+1:]);
        do_cpp(k,ofn,v);

def cmd_arg_auto(args):
    """Generate the cpp output auto*, do this after get-auto-commands"""
    fn = os.path.join(git_root,"abuild","arguments.pickle");
    with open(fn) as F:
        all_cmds = pickle.load(F);
    for k,v in all_cmds.iteritems():
        if "-fno-strict-aliasing" in v.args:
            print k

def cmd_run_cpp_cmake(args):
    """Generate the cpp output cmake"""
    bdir = os.path.join(git_root,"cbuild");
    if os.path.exists(bdir):
        shutil.rmtree(bdir);
    os.makedirs(bdir);

    subprocess.check_call(["cmake","-GNinja",
                           "-DCMAKE_EXPORT_COMPILE_COMMANDS=1",
                           "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                           "-DENABLE_VALGRIND=1",
                           git_root],
                          cwd=bdir);

    with open(os.path.join(bdir,"compile_commands.json")) as F:
        all_cmds = {I["file"]: canonize_args(I["command"],I["file"],I["directory"])
                    for I in json.load(F)};

    bdir = os.path.join(bdir,"cpp");
    for k,v in all_cmds.iteritems():
        assert k.startswith(git_root);
        ofn = os.path.join(bdir,k[len(git_root)+1:]);
        do_cpp(k,ofn,v);

def cmp_content(fromfn,tofn):
    """Write out a file for byte-wise content compare"""
    os.link(fromfn,tofn);

def cmp_elf(fromfn,tofn):
    """Convert an ELF file to a text description"""
    soname = "NONE";
    deps = set();
    for I in subprocess.check_output(["readelf","--wide","-d",fromfn]).splitlines():
        m = re.match(r'^ 0x\S+ \(NEEDED\) .*\[(.*)\]',I);
        if m is not None:
            deps.add(m.group(1));
        m = re.match(r'^ 0x\S+ \(SONAME\) .*\[(.*)\]',I);
        if m is not None:
            soname = m.group(1)

    syms = set();
    for I in subprocess.check_output(["readelf","-s",fromfn]).splitlines():
        if ".symtab" in I:
            break;
        I = re.split(r'\s+',I.strip())
        if len(I) <= 7 or I[4] not in {"GLOBAL","WEAK"} or I[5] == "HIDDEN" or I[7] == "UND":
            continue;
        if I[6] != "UND":
            I[6] = "XX";
        if I[-1].startswith('('):
            syms.add(tuple(I[4:-1]));
        else:
            syms.add(tuple(I[4:]));
    with open(tofn,"wt") as F:
        print >> F,"DEPS:",','.join(sorted(deps));
        print >> F,"SONAME:",soname;
        print >> F,"External Symbols:";
        for I in sorted(syms):
            print >> F, "  ",I;

def scan_install(root,dest):
    """Scan an install tree and produce another diff compatible tree which summarize it."""
    if os.path.exists(dest):
        shutil.rmtree(dest);
    os.makedirs(dest);

    with open(os.path.join(dest,"FILES"),"wt") as F:
        os.chdir(root);
        fns = []
        for curdir, dirs, files in os.walk("."):
            for I in files:
                fns.append(os.path.join(curdir,I));
        fns.sort();
        for fn in fns:
            # Write a list of files and symlinks
            if os.path.islink(fn):
                print >> F,fn,"->",os.readlink(fn),os.path.realpath(fn)[len(root):];
                continue;
            # Set the umask to 0220 before checking modes
            #print >> F,fn,"%o"%(os.stat(fn).st_mode);
            print >> F,fn;

            tofn = os.path.join(dest,fn);
            todir = os.path.dirname(tofn);
            if not os.path.isdir(todir):
                os.makedirs(todir);

            if (fn.endswith("rxe_cfg") or
                fn.endswith(".cmds") or
                fn.endswith(".sh")):
                cmp_content(fn,tofn);
            elif "/bin/" in fn or "/sbin/" in fn:
                cmp_elf(fn,tofn);
            elif (fn.endswith(".h") or
                fn.endswith(".driver") or
                #fn.endswith(".la") or
                fn.endswith(".1") or
                fn.endswith(".3") or
                fn.endswith(".7") or
                fn.endswith(".8") or
                fn.endswith(".conf") or
                fn.endswith("ibacm") or
                fn.endswith("srpd") or
                fn.endswith("srp_daemon")):
                cmp_content(fn,tofn);
            elif ".so" in fn:
                cmp_elf(fn,tofn);
            else:
                print "Did not handle",fn;

def cmd_run_install_auto(args):
    """Build and install using auto*"""
    root = os.path.join(git_root,"abuild","root");
    if os.path.exists(root):
        shutil.rmtree(root);
    for I in sources():
        proj = os.path.basename(I);
        bdir = os.path.join(git_root,"abuild",proj);

        print I
        subprocess.check_call(["make","-j8"],cwd=bdir);
        subprocess.check_call(["make","DESTDIR=%s/"%(root),"install"],cwd=bdir);
    scan_install(root,os.path.join(git_root,"abuild","inst"));

def cmd_run_install_cmake(args):
    """Build and install using cmake"""
    bdir = os.path.join(git_root,"cbuild");
    root = os.path.join(bdir,"root");
    if os.path.exists(root):
        shutil.rmtree(root);

    env = os.environ.copy();
    env["DESTDIR"] = "%s/"%(root);
    subprocess.check_call(["ninja","install"],cwd=bdir,env=env);
    scan_install(root,os.path.join(git_root,"cbuild","inst"));

def cmd_run_install_docker(args):
    """Build and install using cmake, running in all the docker containers"""
    for env in {"centos6","centos7","debian-8","fc24","ubuntu-14.04","ubuntu-16.04"}:
        os.chdir(git_root);
        bdir = os.path.join(git_root,"build-%s"%(env));
        root = os.path.join(bdir, "root");
        if os.path.exists(root):
            shutil.rmtree(root);

        if not os.path.isdir(bdir):
            os.makedirs(bdir);

        print env
        subprocess.check_call(["docker/do_docker.py","make",env])
        subprocess.check_call(["docker/do_docker.py","make",env,"install","DESTDIR=%s"%(root)])
        scan_install(root,os.path.join(git_root,"build-%s"%(env),"inst"));

if __name__ == '__main__':
    git_root = os.getcwd();
    parser = argparse.ArgumentParser(description="""Compare build results
    This has to be run in a sequence:
      buildlib/compare-build.py prepare-auto
      buildlib/compare-build.py get-auto-commands
      buildlib/compare-build.py run-cpp-auto
      buildlib/compare-build.py run-cpp-cmake
      diff -ur abuild/cpp cbuild/cpp
      buildlib/compare-build.py run-install-auto
      buildlib/compare-build.py run-install-cmake
      diff -ur abuild/inst cbuild/inst
    """)
    subparsers = parser.add_subparsers(title="Sub Commands");

    funcs = globals();
    for k,v in funcs.items():
        if k.startswith("cmd_") and inspect.isfunction(v):
            sparser = subparsers.add_parser(k[4:].replace('_','-'),
                                            help=v.__doc__);
            #funcs["args_" + k[4:]](sparser);
            sparser.set_defaults(func=v);
    args = parser.parse_args();
    args.func(args)
    sys.exit(0);
