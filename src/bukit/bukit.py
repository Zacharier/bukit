#!/usr/bin/env python
#
# Copyright 2022 Zacharier
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This utility provides a set of interfaces which are inspired by the following:
https://www.gnu.org/software/make/manual/make.html

In addition, which also supports to speed up the build process by `Ccache`.
For detailed infomation of `Ccache` refer to: https://ccache.dev/
"""

import glob
import os
import re
import shelve
import shutil
import sys
import time
import subprocess
import codecs
import argparse

__version__ = "1.0.0"

LOGO = """\
 __________________________________________________________
|                                                          |

      .______    __    __   __  ___  __  .___________.      
      |   _  \  |  |  |  | |  |/  / |  | |           |      
      |  |_)  | |  |  |  | |  '  /  |  | `---|  |----`      
      |   _  <  |  |  |  | |    <   |  |     |  |           
      |  |_)  | |  `--'  | |  .  \  |  |     |  |           
      |______/   \______/  |__|\__\ |__|     |__|           
                                                    

|                                                          |
|__________________________________________________________|
"""


def say(fmt="", *args, **kwargs):
    """
    Print a formatted message with a specified color.
    """
    colors = {
        "black": "\033[30m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "purple": "\033[35m",
        "azure": "\033[36m",
        "white": "\033[37m",
        None: "\033[32m",
    }
    which = kwargs.get("color")
    newline = kwargs.get("nl", "\n")
    fmt = str(fmt)
    sys.stdout.write(colors[which])
    sys.stdout.write(args and fmt % args or fmt)
    sys.stdout.write("\033[0m")  # Erase color
    sys.stdout.write("\033[K")  # Erase remaining characters
    sys.stdout.write(newline)
    sys.stdout.flush()


def break_str(s):
    """
    Break a string into multiline text.
    """
    return " \\\n\t".join(s)


def shrink_str(s):
    """
    Combine multi-whitespaces in string
    """
    return " ".join(filter(None, s.split(" ")))


def globs(args):
    """
    Glob all files and flatten to list.
    """
    srcs = []
    for path in args:
        if path.startswith("~/"):
            path = os.path.expanduser(path)
        srcs += glob.glob(path)
    return srcs


def remove_file(f):
    """
    Remove a file if exists.
    """
    if os.path.exists(f):
        os.remove(f)
        return True
    return False


def subcall(cmd, stdout=sys.stdout, stderr=sys.stderr, exit_on_error=True):
    """
    Fork and execute a new command.
    """
    p = subprocess.Popen(cmd, shell=True, stdout=stdout)
    out, err = p.communicate()
    r = p.wait()
    if r != 0 and exit_on_error:
        sys.exit(r)
    return r, out and out.decode("utf-8"), err and err.decode("utf-8")


class ArgsParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("%s\n" % message)
        self.print_help()
        sys.exit(2)


class Flags(list):
    def __str__(self):
        return " ".join(iter(self))


class LdLibs(list):
    def __str__(self):
        return break_str(iter(self))


class Includes(list):
    def __str__(self):
        return " ".join(("-I %s" % arg for arg in iter(self)))


class Scope(dict):
    """
    A extended dict.
    """

    def __init__(self, d):
        dict.__init__(self, d)

    def extend(self, parent):
        for key, val in parent.items():
            child_val = self.get(key)
            if isinstance(child_val, list):
                child_val.extend(val)
            elif child_val is None:
                self[key] = val


class MakeRule:
    """
    Generate a makefile rule which has a following style:
    TARGETS: PREREQUISITES (; COMMAND)
        COMMAND
    """

    def __init__(self, target, prereqs, command):
        self._target = target
        self._prereqs = prereqs
        self._command = command

    def target(self):
        return self._target

    def prereqs(self):
        return self._prereqs

    def command(self):
        return self._command

    def __str__(self):
        raise NotImplementedError


class PhonyRule(MakeRule):
    """
    Generate a `.PHONY` rule has a following style:
    TARGETS: PREREQUISITES
    or:
    TARGETS:
        COMMANDS
    """

    def __init__(self, name, prereqs=(), command=None):
        MakeRule.__init__(self, name, prereqs, command)

    def __str__(self):
        s = "%s : %s" % (self._target, break_str(self._prereqs))
        if self._command:
            s += "\n\t" + self._command
        return s


class CleanRule(PhonyRule):
    """
    Generate a rule which cleans all of targets generated by makefile.
    """

    def __init__(self, files):
        target = "clean"
        command = "-rm -fr " + break_str(sorted(set(files)))
        PhonyRule.__init__(self, target, command=command)


class NoRecipeRule(PhonyRule):
    """
    Generate a makefile rule which has a following style:
    TARGETS: PREREQUISITES;
    """

    def __str__(self):
        return PhonyRule.__str__(self) + ";"


class FileMakeRule(MakeRule):
    """
    Generate a makefile rule which has a following style:
    TARGETS: PREREQUISITES
        COMMAND
    NOTE: The TARGETS must be a file.
    """

    def __str__(self):
        return "%s : %s\n\t%s" % (
            self._target,
            break_str(self._prereqs),
            shrink_str(self._command),
        )


class CompileRule(FileMakeRule):
    """
    Generate a rule which compiles source file to object file.
    """

    def __init__(self, name, source, prereqs, kwargs):
        target = os.path.join(kwargs["output"], "objs", name, source + ".o")
        kwargs["target"] = target
        kwargs["srcs"] = source
        if source.endswith(".c"):
            fmt = "%(ccache)s %(cc)s -o %(target)s -c %(optimize)s %(cflags)s %(incs)s %(srcs)s"
        else:
            fmt = "%(ccache)s %(cxx)s -o %(target)s -c %(optimize)s %(cxxflags)s %(incs)s %(srcs)s"
        command = fmt % kwargs
        FileMakeRule.__init__(self, target, prereqs, command)


class ElfRule(FileMakeRule):
    """
    Generate a rule which links some object files.
    """

    def __init__(self, target, objs, libs, shared, kwargs):
        kwargs["target"] = target
        kwargs["objs"] = break_str(objs)
        kwargs["shared"] = "-shared" if shared else ""
        fmt = "%(ccache)s %(cxx)s %(shared)s -o %(target)s %(objs)s %(ldflags)s"
        kwargs["ldlibs"].extend(libs)
        if kwargs["ldlibs"]:
            if sys.platform == "darwin":  # OS X
                fmt += " -Xlinker %(ldlibs)s"
            else:
                fmt += ' -Xlinker "-(" %(ldlibs)s -Xlinker "-)"'
        command = fmt % kwargs
        FileMakeRule.__init__(self, target, objs + libs, command)


class BinaryRule(ElfRule):
    """
    Generate a rule which links some object files.
    """

    def __init__(self, name, objs, libs, kwargs):
        target = os.path.join(kwargs["output"], "bin", name)
        ElfRule.__init__(self, target, objs, libs, False, kwargs)


class TestRule(ElfRule):
    """
    Generate a rule which links some object files.
    """

    def __init__(self, name, objs, libs, kwargs):
        target = os.path.join(kwargs["output"], "test", name)
        ElfRule.__init__(self, target, objs, libs, False, kwargs)


class SharedRule(ElfRule):
    """
    Generate a rule which links some object files to a Shared Object file.
    """

    def __init__(self, name, objs, libs, kwargs):
        target = os.path.join(kwargs["output"], "lib", "lib%s.so" % name)
        ElfRule.__init__(self, target, objs, libs, True, kwargs)


class StaticRule(FileMakeRule):
    """
    Generate a rule which archive some object files to an archived file.
    """

    def __init__(self, name, objs, kwargs):
        target = os.path.join(kwargs["output"], "lib", "lib%s.a" % name)
        kwargs["target"] = target
        kwargs["objs"] = break_str(objs)
        command = "ar rcs %(target)s %(objs)s" % kwargs
        FileMakeRule.__init__(self, target, objs, command)


class PrebuiltRule(FileMakeRule):
    """
    Generate a rule which copy linked file to a new file.
    """

    def __init__(self, lib, kwargs):
        target = os.path.join(kwargs["output"], "lib", os.path.basename(lib))
        command = "cp %s %s" % (lib, target)
        FileMakeRule.__init__(self, target, [lib], command)


class Context:
    """
    Context
    """

    def __init__(self):
        self._symbol_table = {}
        self._artifact_table = {}

    def is_declared(self, name):
        return name in self._symbol_table

    def declare(self, name, deps):
        assert name not in self._symbol_table, "`%s` is already declared" % name
        dep_list = list(deps)
        for dep_name in deps:
            child_deps = self._symbol_table.get(dep_name)
            assert child_deps is not None, "`%s` was not found" % dep_name
            dep_list.extend(child_deps)

        self._symbol_table[name] = dep_list

    def deps_of(self, name):
        return self._symbol_table[name]

    def define(self, name, target):
        assert name not in self._artifact_table, "`%s` is already defined" % name
        self._artifact_table[name] = target

    def resolve(self, name):
        return self._artifact_table.get(name)


class Artifact:
    """
    An abstract class which produces a snippet of makefile. In which
    a snippet can makes a executable file(.out) or a shared object(.so)
    or a archived file(.a).
    """

    def __init__(self, ctx, name, srcs, deps, kwargs):
        self._ctx = ctx
        self._name = name
        self._srcs = srcs
        self._deps = deps
        self._objs = []
        self._libs = []
        self._kwargs = kwargs

    def name(self):
        return self._name

    def _search_prereqs(self, source):
        # Gcc include syntax:
        # https://gcc.gnu.org/onlinedocs/cpp/Include-Syntax.html
        # Gcc search path:
        # https://gcc.gnu.org/onlinedocs/cpp/Search-Path.html#Search-Path
        quote_pat = re.compile(r'^#[^\S\r\n]*include[^\S\r\n]+"([^"]+)"', re.M)
        sys_pat = re.compile(r"^#[^\S\r\n]*include[^\S\r\n]+<([^>]+)>", re.M)

        seen = set()

        def search_path(headers, incs):
            headers = [header for header in headers if header not in seen]
            seen.update(headers)
            paths = []
            for header in headers:
                for inc in incs:
                    path = os.path.join(inc, header)
                    if os.path.exists(path):
                        paths.append(path)
                        break
            return paths

        spec_incs = self._kwargs["incs"]
        incs = list(spec_incs)
        queue = [source]
        prereqs = []
        while queue:
            first = queue.pop(0)
            prereqs.append(first)
            with codecs.open(first, encoding="utf-8") as f:
                content = f.read()
                curr = os.path.dirname(first)
                queue += search_path(quote_pat.findall(content), [curr] + incs)
                queue += search_path(sys_pat.findall(content), spec_incs)

        return prereqs

    def _build_objs(self):
        obj_rules = []
        for i, source in enumerate(self._srcs):
            n = len(self._srcs)
            percent = (i + 1) * 100 / n
            nl = "\n" if i + 1 == n else "\r"
            say("%s\t%3d%%: %s", self._name, percent, source, nl=nl)
            prereqs = self._search_prereqs(source)
            rule = CompileRule(self._name, source, prereqs, self._kwargs)
            obj_rules.append(rule)
        return obj_rules

    def _build_out(self):
        raise NotImplementedError

    def build(self):
        obj_rules = self._build_objs()
        self._objs.extend([rule.target() for rule in obj_rules])
        for dep in self._deps:
            target = self._ctx.resolve(dep)
            assert target, "unrecognized deps: %s" % dep
            self._libs.append(target)
        rule = self._build_out()
        self._ctx.define(self._name, rule.target())
        nop_rule = NoRecipeRule(self._name, [rule.target()])
        return [nop_rule, rule] + obj_rules


class Binary(Artifact):
    """
    Binary file.
    """

    def _build_out(self):
        return BinaryRule(self._name, self._objs, self._libs, self._kwargs)


class Test(Artifact):
    """
    Unit Test.
    """

    def _build_out(self):
        return TestRule(self._name, self._objs, self._libs, self._kwargs)


class SharedLibrary(Artifact):
    """
    Shared Object.
    """

    def _build_out(self):
        return SharedRule(self._name, self._objs, self._libs, self._kwargs)


class StaticLibrary(Artifact):
    """
    Static Libary
    """

    def _build_out(self):
        return StaticRule(self._name, self._objs, self._kwargs)


class PrebuiltLibrary(Artifact):
    """
    Prebuilt(shared) Libary
    """

    def _build_objs(self):
        return []

    def _build_out(self):
        def find_lib(ext):
            lib_name = "lib%s%s" % (self._name, ext)
            for d in self._srcs:
                path = os.path.join(d, lib_name)
                if os.path.exists(path):
                    return path

        lib_path = find_lib(".so") or find_lib(".a")
        assert lib_path, "lib%s.so or lib%s.a was not found in: %s" % (
            self._name,
            self._name,
            self._srcs,
        )
        return PrebuiltRule(lib_path, self._kwargs)


class Module:
    """
    Module represents a builder which builds a Makefile file.
    """

    def __init__(self):
        self._ctx = Context()
        self._protos = {}
        self._artifacts = []
        self._phonies = ["all", "clean"]
        self._vars = {}
        self.config(
            cc="cc",
            cxx="c++",
            protoc="protoc",
            ccache="",
            output="output",
            **{
                "incs": [],
                "optimize": False,
                "cflags": [],
                "cxxflags": [],
                "ldflags": [],
                "ldlibs": [],
            }
        )

    def _sanitize(
        self,
        incs=None,
        optimize=None,
        cflags=None,
        cxxflags=None,
        ldflags=None,
        ldlibs=None,
    ):
        settings = {}
        if optimize is not None:
            if isinstance(optimize, bool):
                settings["optimize"] = "-O3" if optimize is True else "-O0"
            else:
                settings["optimize"] = optimize
        if incs is not None:
            settings["incs"] = Includes(incs)
        if cflags is not None:
            settings["cflags"] = Flags(cflags)
        if cxxflags is not None:
            settings["cxxflags"] = Flags(cxxflags)
        if ldflags is not None:
            flags = Flags()
            libs = LdLibs()
            for ldflag in ldflags:
                ldflag = ldflag.strip()
                if ldflag.startswith("-") and not ldflag.startswith("-l"):
                    flags.append(ldflag)
                else:
                    libs.append(ldflag)
            settings["ldflags"] = flags
            if libs:
                settings["ldlibs"] = libs
        if ldlibs is not None:
            settings["ldlibs"] = LdLibs(ldlibs + settings.get("lidlibs", []))
        return settings

    def config(
        self, cc=None, cxx=None, protoc=None, ccache=None, output=None, **settings
    ):
        for name, val in [
            ("cc", cc),
            ("cxx", cxx),
            ("ccache", ccache),
            ("protoc", protoc),
            ("output", output),
        ]:
            if val is not None:
                self._vars[name] = val
        self._vars.update(self._sanitize(**settings))

    def output(self):
        return self._vars["output"]

    def protoc(self):
        return self._vars["protoc"]

    def _add_artifact(self, cls, name, srcs, deps, protos, kwargs):
        sources = globs(srcs)
        protobufs = globs(protos)
        sources.extend([proto.replace(".proto", ".pb.cc") for proto in protobufs])
        assert sources, "no matched files were found in: %s" % name
        self._protos[name] = protobufs
        scope = Scope(self._sanitize(**kwargs))
        scope.extend(self._vars)
        artifact = cls(self._ctx, name, sources, deps, scope)
        self._ctx.declare(name, deps)
        self._artifacts.append(artifact)

    def add_binary(self, name, srcs, deps, protos, kwargs):
        self._add_artifact(Binary, name, srcs, deps, protos, kwargs)

    def add_test(self, name, srcs, deps, protos, kwargs):
        self._add_artifact(Binary, name, srcs, deps, protos, kwargs)

    def add_shared(self, name, srcs, deps, protos, kwargs):
        self._add_artifact(SharedLibrary, name, srcs, deps, protos, kwargs)

    def add_static(self, name, srcs, protos, kwargs):
        self._add_artifact(StaticLibrary, name, srcs, (), protos, kwargs)

    def add_prebuilt(self, name, srcs, kwargs):
        self._add_artifact(PrebuiltLibrary, name, srcs, (), (), kwargs)

    def _generate(self, protos):
        for proto in set(protos):
            pbname, _ = os.path.splitext(proto)
            pbh, pbcc = pbname + ".pb.h", pbname + ".pb.cc"
            if os.path.exists(pbh) and os.path.exists(pbcc):
                pbh_mtime = os.path.getmtime(pbh)
                pbcc_mtime = os.path.getmtime(pbcc)
                proto_mtime = os.path.getmtime(proto)
                if pbh_mtime > proto_mtime and pbcc_mtime > proto_mtime:
                    continue

            proto_dirs = set([os.path.dirname(path) for path in protos])
            proto_paths = " ".join(
                ["--proto_path " + proto_dir for proto_dir in proto_dirs]
            )
            cmd = "%s %s --cpp_out=%s %s" % (
                self.protoc(),
                proto_paths,
                os.path.dirname(proto),
                proto,
            )
            say(cmd, color="yellow")
            subcall(cmd)

    def _make(self, rules_table, makefile):
        notices = [
            "# file : Makefile",
            "# brief: this file was generated by `bukit`",
            "# date : %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        ]

        targets = set()
        names = []
        rules_list = []
        for name, rules in rules_table.items():
            names.append(name)
            rules_list.append(rules)
            for rule in rules:
                if isinstance(rule, FileMakeRule):
                    targets.add(rule.target())
                    dirc = os.path.dirname(rule.target())
                    if not os.path.exists(dirc):
                        os.makedirs(dirc)

        rules = []
        rules.append(PhonyRule(".PHONY", self._phonies))
        rules.append("")
        rules.append(PhonyRule("all", names))

        for r in rules_list:
            rules.append("")
            rules.append("")
            rules.extend(r)

        rules.append("")
        rules.append("")
        rules.append(CleanRule(sorted(targets)))

        with codecs.open(makefile, "w", encoding="utf-8") as out:
            out.write("\n".join(notices))
            out.write("\n")
            out.write("\n")
            for rule in rules:
                out.write(str(rule))
                out.write("\n")

    def build(self, makefile, name):
        assert name is None or self._ctx.is_declared(name), "unknown name: %s" % name
        if name is None:
            protos = [proto for protos in self._protos.values() for proto in protos]
            self._generate(protos)
            artifacts = self._artifacts
        else:
            protos = []
            names = [name] + self._ctx.deps_of(name)
            for name in names:
                protos.extend(self._protos.get(name, []))
            self._generate(protos)
            artifacts = [
                artifact for artifact in self._artifacts if artifact.name() in names
            ]
        rules_table = {}
        for artifact in artifacts:
            rules = artifact.build()
            rules_table[artifact.name()] = rules
        self._make(rules_table, makefile)
        return protos, rules_table


def api(module):
    """
    Api offers some functions which can be invoked by BUILD.
    """

    def config(**kwargs):
        module.config(**kwargs)

    def binary(name, srcs, protos=(), deps=(), **kwargs):
        module.add_binary(name, srcs, deps, protos, kwargs)

    def test(name, srcs, protos=(), deps=(), **kwargs):
        module.add_test(name, srcs, deps, protos, kwargs)

    def library(
        name, srcs=(), protos=(), deps=(), shared=False, prebuilt=False, **kwargs
    ):
        if prebuilt:
            module.add_prebuilt(name, srcs, kwargs)
        elif shared:
            module.add_shared(name, srcs, deps, protos, kwargs)
        else:
            module.add_static(name, srcs, protos, kwargs)

    return dict(locals(), **{name.upper(): func for name, func in locals().items()})


class Template:
    """
    Build Template which generates a BUILD file.
    """

    def format(self, name):
        lines = [
            "config(",
            '    cc="cc",',
            '    cxx="c++",',
            "    cflags=[",
            '        "-g",',
            '        "-std=c11",',
            '        "-pipe",',
            '        "-W",',
            '        "-Wall",',
            '        "-fPIC",',
            '        "-fno-omit-frame-pointer",',
            "    ],",
            "    cxxflags=[",
            '        "-g",',
            '        "-std=c++11",',
            '        "-pipe",',
            '        "-W",',
            '        "-Wall",',
            '        "-fPIC",',
            '        "-fno-omit-frame-pointer",',
            "    ],",
            '    ldflags=["-L/usr/local/lib"],',
            ")",
            "",
            "",
            "binary(",
            '    name="%s",',
            '    incs=["./", "src/"],',
            '    srcs=["./*.cc", "./*.cpp", "src/*.cc", "src/*.cpp"],',
            ")",
        ]
        return "\n".join(lines) % name


class Storage:
    """
    Load and store a shelve db, also compare with current cache.

    mode: 'r' (default) for read-only access, 'w' for read-write access of an
    existing database, 'c' for read-write access to a new or existing database.
    """

    def __init__(self, mode="r"):
        self._path = ".bukit"
        if mode == "r" and not os.path.exists(self._path):
            self._manifest_db = {}
            self._target_db = {}
        else:
            if not os.path.exists(self._path):
                os.mkdir(self._path)
            self._manifest_db = shelve.open(os.path.join(self._path, "manifest"), mode)
            self._target_db = shelve.open(os.path.join(self._path, "targets"), mode)

    def path(self):
        return self._path

    def protos(self):
        return self._manifest_db.get("meta/protos")

    def output(self):
        return self._manifest_db.get("meta/output")

    def query(self, name=None, mode=None):
        if name is None:
            targets = []
            for key, fname in self._manifest_db.items():
                if key.startswith("artifact/"):
                    if mode is None or os.access(fname, mode):
                        targets.append(fname)
            return targets
        target = self._manifest_db.get("artifact/" + name)
        return [target] if target is not None else []

    def save(self, output, protos, rules_table):
        cache = {}
        for name, rs in rules_table.items():
            for r in rs:
                if isinstance(r, NoRecipeRule):
                    name, fname = r.target(), r.prereqs()[0]
                    self._manifest_db["artifact/" + name] = fname
                else:
                    cache[r.target()] = r
        self._purge(cache, protos)
        self._target_db.clear()
        self._target_db.update(cache)
        self._manifest_db["meta/protos"] = protos
        self._manifest_db["meta/output"] = output

    def _purge(self, cache, protos):
        for target, rule in cache.items():
            old_rule = self._target_db.get(target)
            if old_rule and (
                rule.prereqs() != old_rule.prereqs()
                or rule.command() != old_rule.command()
            ):
                remove_file(target)
        expired_keys = set(self._target_db.keys()) - set(cache.keys())
        for key in expired_keys:
            remove_file(key)
        for target, rule in self._target_db.items():
            if set(rule.prereqs()) & expired_keys:
                remove_file(target)
        for proto in set(self.protos() or ()) - set(protos):
            pbname, _ = os.path.splitext(proto)
            remove_file(pbname + ".pb.h")
            remove_file(pbname + ".pb.cc")

    def close(self):
        if not isinstance(self._target_db, dict):
            self._target_db.close()
        if not isinstance(self._manifest_db, dict):
            self._manifest_db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Bukit:
    """
    Collect all of rules and generate a makefile file.
    """

    def __init__(self):
        pass

    def create(self, options):
        say("create...")
        tpl = Template()
        content = tpl.format(options.name)
        with codecs.open("BUILD", "w", encoding="utf-8") as f:
            f.write(content)
        say("the `BUILD` has been generated in the current directory")

    def build(self, options):
        def execute(path, globals):
            with codecs.open(path, encoding="utf-8") as f:
                code = compile(f.read(), path, "exec")
                exec(code, globals)

        say("build...")
        module = Module()
        module.config(optimize=options.optimize)
        execute("BUILD", api(module))
        protos, rules_table = module.build("Makefile", options.name)
        with Storage("c") as s:
            s.save(module.output(), protos, rules_table)

        say("make...")
        cmd = "make %s" % options.name or "all"
        if options.jobs is not None:
            cmd += " -j %s" % options.jobs
        say(cmd, color="yellow")
        subcall(cmd)

    def run(self, options):
        self.build(options)
        with Storage("r") as s:
            targets = s.query(options.name, mode=os.X_OK)
        if len(targets) != 1:
            assert options.name is not None, "a name must be specified by command args"
            assert options.name is None, "unknown name: %s" % options.name
        say("run...")
        cmd = targets[0]
        if options.args:
            cmd += " " + options.args
        say(cmd, color="yellow")
        subcall(cmd)

    def clean(self, options):
        say("clean...")
        makefile = "Makefile"
        if not options.all:
            if os.path.exists(makefile):
                cmd = "make clean"
                say(cmd, color="yellow")
                subcall(cmd, sys.stdout)
        else:
            with Storage("r") as s:
                path, protos, output = s.path(), s.protos(), s.output()

            remove_file(makefile)
            for proto in protos or ():
                pbname, _ = os.path.splitext(proto)
                remove_file(pbname + ".pb.h")
                remove_file(pbname + ".pb.cc")
            if output:
                shutil.rmtree(output, True)
            shutil.rmtree(path, True)


def do_args():
    parser = ArgsParser(add_help=True)
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s " + __version__,
    )
    subparsers = parser.add_subparsers(dest="command", help=None, title="commands")
    parser_create = subparsers.add_parser("create", help="create BUILD")
    parser_build = subparsers.add_parser("build", help="build project")
    parser_run = subparsers.add_parser("run", help="run project")
    parser_clean = subparsers.add_parser("clean", help="clean project")
    for sub_parser in (parser_create, parser_build, parser_run):
        sub_parser.add_argument(
            "--name",
            type=str,
            default="app",
            required=False,
            help="artifact name. eg: app",
        )
        if sub_parser in (parser_build, parser_run):
            sub_parser.add_argument(
                "--optimize",
                default=False,
                action="store_true",
                help="enable '-O3' optimization level, default: False",
            )
            sub_parser.add_argument(
                "--jobs",
                type=int,
                default=None,
                required=False,
                help="parallel make project",
            )
    parser_run.add_argument(
        "--args",
        type=str,
        default="",
        required=False,
        help="pass command line args to executable",
    )
    parser_clean.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="clean all files generated by Bukit",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return parser.parse_args()


def main():
    say(LOGO)
    args = do_args()
    bukit = Bukit()
    if args.command == "create":
        bukit.create(args)
    elif args.command == "build":
        bukit.build(args)
    elif args.command == "run":
        bukit.run(args)
    elif args.command == "clean":
        bukit.clean(args)


if __name__ == "__main__":
    main()
