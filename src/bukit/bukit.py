#!/usr/bin/env python3
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


class ArgError(IOError):
    pass


def say(fmt, *args, **kwargs):
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
    sys.stdout.write(colors[which] + (args and fmt % args or fmt) + "\033[0m")
    sys.stdout.write(newline)
    sys.stdout.flush()


def break_str(prereqs):
    """
    Break a string into multiline text.
    """
    return " \\\n\t".join(prereqs)


def subcall(cmd, stdout=subprocess.PIPE):
    """
    Fork and execute a new command.
    """
    p = subprocess.Popen(cmd, shell=True, stdout=stdout)
    out, err = p.communicate()
    r = p.wait()
    return r, out and out.decode("utf-8"), err and err.decode("utf-8")


class Options(dict):
    """
    A parsed options from command line.
    """

    def __init__(self, d=None, **extra):
        d = d or {}
        dict.__init__(self, d, **extra)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None


class OptionsParser:
    """
    Parse command line into a options object.
    """

    def __init__(self):
        self._args = {}
        self._actions = {}
        self.add_option("--help", help="Show this help", typo="bool", default=False)

    def add_option(self, option, help, typo="str", required=False, default=None):
        self._actions[option] = (typo, help, required, default)
        if not required:
            self._args[option[2:]] = default

    def parse_args(self, argv):
        def convert(key, s):
            types = {
                "str": str,
                "int": int,
                "float": float,
            }
            try:
                return types[key](s)
            except KeyError:
                return None

        if "--help" in argv:
            raise ArgError()

        opts = Options(self._args)
        size = len(argv)
        i = 0
        while i < size:
            arg = argv[i]
            if arg not in self._actions:
                raise ArgError("option %s is unrecognized" % arg)
            typo, _, __, ___ = self._actions[arg]
            if typo == "bool":
                opts[arg[2:]] = True
            else:
                i += 1
                if i == size:
                    raise ArgError("option %s: too few arguments" % arg)
                val = convert(typo, argv[i])
                if val is None:
                    raise ArgError("option %s: %s is required" % (arg, typo))
                opts[arg[2:]] = val
            i += 1
        for option, (_, _, required, _) in self._actions.items():
            if required and option[2:] not in opts:
                raise ArgError("option %s is required" % option)
        return opts

    def help(self, cmd="general"):
        s = cmd.title() + " Options:\n"
        last = ""
        for key, (_, help, __, ___) in self._actions.items():
            if "--help" == key:
                last = "  %-20s %s\n" % (key, help)
            else:
                s += "  %-20s %s\n" % (key, help)
        return s + last


class ArgumentParser:
    """
    Parse command and options from command line.
    """

    def __init__(self, name, version=None):
        self._commands = []
        self._command_map = {}
        self._name = name
        self._version = version

        self.add_command("version", "Show version")
        self.add_command("help", "Show help")

    def usage(self, command="<command>"):
        return "Usage:\n  %s %s [options]\n\n" % (self._name, command)

    def add_command(self, command, help, option_parser=None):
        self._commands.insert(-1, command)
        self._command_map[command] = (help, option_parser)

    def parse(self, argv):
        if len(argv) == 0 or argv[0] == "help":
            self.print_help(self.help())
        if self._version and argv[0] == "version":
            self.print_version(self._version)
        if argv[0] not in self._command_map:
            self.print_help(self.help(), "command %s: unrecognized" % argv[0])
        _, parser = self._command_map[argv[0]]
        if parser is None:
            return argv[0], None
        try:
            options = parser.parse_args(argv[1:])
            return argv[0], options
        except ArgError as e:
            self.print_help(self.usage(argv[0]) + parser.help(argv[0]), e)

    def print_help(self, help=None, error=None, stream=sys.stdout):
        lines = [help or self.help()]
        if isinstance(error, ArgError):
            error = str(error)
        if error:
            lines.append(error)
        stream.write("\n".join(lines))
        stream.write("\n")
        sys.exit(-1 if error else 0)

    def print_version(self, version):
        sys.stdout.write(version)
        sys.stdout.write("\n")
        sys.exit(0)

    def help(self):
        h = self.usage()
        h += "Commands:\n"
        for cmd in self._commands:
            h += "  %-10s%s\n" % (cmd, self._command_map[cmd][0])
        return h


class Scope(dict):
    """
    A extended dict.
    """

    def __init__(self, d):
        dict.__init__(self, d)

    def extend(self, parent):
        for key, val in parent.items():
            sub_val = self.get(key)
            if isinstance(sub_val, list):
                for e in val:
                    sub_val.insert(0, e)
            else:
                self[key] = val


class Flags(list):
    def __str__(self):
        return " ".join(iter(self))


class LdLibs(list):
    def __str__(self):
        return break_str(iter(self))


class Includes(list):
    def __str__(self):
        return " ".join(("-I %s" % arg for arg in iter(self)))


class MakeRule:
    """
    Generate a makefile rule which has a following style:
    TARGETS: PREREQUISITES (; COMMAND)
        COMMAND
    """

    def __init__(self, target, prereqs=(), command=""):
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
        prereqs = break_str(self._prereqs)
        s = "%s : %s" % (self._target, prereqs)
        if self._command:
            commands = (
                self._command if isinstance(self._command, list) else [self._command]
            )
            for command in commands:
                command = " ".join(filter(None, self._command.split(" ")))
                s += "\n\t%s" % command
        return s


class NopRule(MakeRule):
    """
    Generate a makefile rule which has a following style:
    TARGETS: PREREQUISITES;
    """

    def __init__(self, target, prereqs):
        MakeRule.__init__(self, target, prereqs, None)

    def __str__(self):
        return MakeRule.__str__(self) + ";"


class CompileRule(MakeRule):
    """
    Generate a rule which compiles source file to object file.
    """

    def __init__(self, name, source, prereqs, args):
        target = os.path.join(args["output"], "objs", name, source + ".o")
        args["target"] = target
        args["srcs"] = source
        cc_fmt = "%(ccache)s %(cc)s -o %(target)s -c %(cflags)s %(incs)s " "%(srcs)s"
        cxx_fmt = (
            "%(ccache)s %(cxx)s -o %(target)s -c %(cxxflags)s %(incs)s " "%(srcs)s"
        )
        fmt = cc_fmt if source.endswith(".c") else cxx_fmt
        command = fmt % args
        MakeRule.__init__(self, target, prereqs, command)


class LinkableRule(MakeRule):
    """
    Generate a rule which links some object files.
    """

    def __init__(self, name, prereqs, objs, args, test=False):
        target = os.path.join(args["output"], "test" if test else "bin", name)
        args["target"] = target
        args["objs"] = break_str(objs)
        fmt = (
            "%(ccache)s %(cxx)s -o %(target)s %(objs)s %(ldflags)s "
            '-Xlinker "-(" %(ldlibs)s -Xlinker "-)"'
        )
        command = fmt % args
        MakeRule.__init__(self, target, prereqs, command)


class SharedRule(MakeRule):
    """
    Generate a rule which links some object files to a Shared Object file.
    """

    def __init__(self, name, prereqs, objs, args):
        target = os.path.join(args["output"], "lib", "lib%s.so" % name)
        args["target"] = target
        args["objs"] = break_str(objs)
        fmt = (
            "%(ccache)s %(cxx)s -o %(target)s -shared "
            '%(objs)s %(ldflags)s -Xlinker "-(" %(ldlibs)s -Xlinker "-)"'
        )
        command = fmt % args
        MakeRule.__init__(self, target, prereqs, command)


class StaticRule(MakeRule):
    """
    Generate a rule which archive some object files to an archived file.
    """

    def __init__(self, name, prereqs, objs, args):
        target = os.path.join(args["output"], "lib", "lib%s.a" % name)
        args["target"] = target
        args["objs"] = break_str(objs)
        command = "ar rcs %(target)s %(objs)s" % args
        MakeRule.__init__(self, target, prereqs, command)


class PrebuiltRule(MakeRule):
    """
    Generate a rule which copy linked file to a new file.
    """

    def __init__(self, name, prereqs, lib, args):
        target = os.path.join(args["output"], "lib", os.path.basename(lib))
        command = "cp %s %s" % (lib, target)
        MakeRule.__init__(self, target, prereqs, command)


class CleanRule(MakeRule):
    """
    Generate a rule which cleans all of targets generated by makefile.
    """

    def __init__(self, targets):
        target = "clean"
        command = "-rm -fr " + break_str(sorted(set(targets)))
        MakeRule.__init__(self, target, (), command)


class Context:
    """
    Context
    """

    def __init__(self, storage):
        self._storage = storage
        self._lib_map = {}
        self._name_map = {}
        self._src_map = {}

    def storage(self):
        return self._storage

    def get_deps(self, name):
        return self._name_map[name]

    def is_defined(self, name):
        return name in self._name_map

    def define(self, name, deps):
        dep_list = list(deps)
        for dep_name in deps:
            child_deps = self._name_map.get(dep_name)
            assert child_deps is not None, "`%s` was not found" % dep_name
            dep_list.extend(child_deps)

        self._name_map[name] = dep_list

    def put_lib(self, name, target):
        self._lib_map[name] = target

    def get_lib(self, name):
        return self._lib_map.get(name)

    def put_prereqs(self, src, prereqs):
        self._src_map[src] = prereqs

    def get_prereqs(self, src):
        return self._src_map.get(src)


class Artifact:
    """
    An abstract class which produces a snippet of makefile. In which
    a snippet can makes a executable file(.out) or a shared object(.so)
    or a archived file(.a).
    """

    def __init__(self, ctx, name, args, srcs, deps):
        self._ctx = ctx
        self._name = name
        self._args = args
        self._srcs = srcs
        self._deps = deps
        self._objs = []
        self._rule = None
        self._obj_rules = []

    def name(self):
        return self._name

    def rules(self):
        nop_rule = NopRule(self._name, [self._rule.target()])
        return [nop_rule, self._rule] + self._obj_rules

    def targets(self):
        return [rule.target() for rule in [self._rule] + self._obj_rules]

    def _analyze(self):
        pattern = re.compile(r'^#include\s+"([^"]+)"', re.M)

        def expand(headers, incs):
            prereq_paths = []
            for header in headers:
                paths = [os.path.join(include, header) for include in incs]
                for path in paths:
                    if os.path.exists(path):
                        prereq_paths.append(path)
                        break
            return prereq_paths

        def search(source):
            prereq_paths = []
            # Create a dummy of original `incs` to append.
            incs = list(self._args.get("incs", []))
            seen = set()
            queue = [source]
            parent = os.path.dirname(source)
            if parent:
                incs.append(parent)
            while queue:
                first = queue.pop(0)
                prereq_paths.append(first)
                with open(first) as f:
                    headers = pattern.findall(f.read())
                    new_headers = filter(lambda x: x not in seen, headers)
                    queue += expand(new_headers, incs)
                    seen.update(new_headers)
            return prereq_paths

        fmt = "[%%%dd/%%d] analyze %%s" % len(str(len(self._srcs)))
        for i, source in enumerate(self._srcs):
            say(fmt, i + 1, len(self._srcs), source)
            prereqs = self._ctx.get_prereqs(source)
            if prereqs is None:
                prereqs = search(source)
                self._ctx.put_prereqs(source, prereqs)
            rule = CompileRule(self._name, source, prereqs, self._args)
            self._objs.append(rule.target())
            self._obj_rules.append(rule)

    def build(self):
        self._analyze()
        self._finalize()

    def _finalize(self):
        pass

    def save(self):
        storage = self._ctx.storage()
        for obj_rule in self._obj_rules:
            storage.put_target(
                obj_rule.target(), obj_rule.prereqs(), obj_rule.command(), True
            )
        rule = self._rule
        storage.put_target(rule.target(), rule.prereqs(), rule.command(), False)
        storage.put_artifact(self._name, rule.target())


class LinkableFile(Artifact):
    """
    Linkable libary or binary.
    """

    def build(self):
        self._analyze()
        for dep in self._deps:
            target = self._ctx.get_lib(dep)
            assert target, "unrecognized deps: %s" % dep
            self._objs.append(target)
        self._finalize()


class Binary(LinkableFile):
    """
    Binary file.
    """

    def _finalize(self):
        self._rule = LinkableRule(self._name, self._objs, self._objs, self._args)


class Test(LinkableFile):
    """
    Unit Test.
    """

    def _finalize(self):
        self._rule = LinkableRule(self._name, self._objs, self._objs, self._args, True)


class SharedLibrary(LinkableFile):
    """
    Shared Object.
    """

    def _finalize(self):
        self._rule = SharedRule(self._name, self._objs, self._objs, self._args)
        self._ctx.put_lib(self._name, self._rule.target())


class StaticLibrary(Artifact):
    """
    Static Libary
    """

    def _finalize(self):
        self._rule = StaticRule(self._name, self._objs, self._objs, self._args)
        self._ctx.put_lib(self._name, self._rule.target())


class PrebuiltLibrary(Artifact):
    """
    Prebuilt(shared) Libary
    """

    def build(self):
        def find_lib(ext):
            name, dircs = self._name, self._srcs
            for d in dircs:
                path = os.path.join(d, "lib%s%s" % (name, ext))
                if os.path.exists(path):
                    return path

        lib_path = find_lib(".so") or find_lib(".a")
        assert lib_path, "lib%s.so or lib%s.a was not found in: %s" % (
            self._name,
            self._srcs,
        )
        self._rule = PrebuiltRule(self._name, [lib_path], lib_path, self._args)
        self._ctx.put_lib(self._name, self._rule.target())


def globs(args):
    srcs = []
    for path in args:
        if path.startswith("~/"):
            path = os.path.expanduser(path)
        srcs += glob.glob(path)
    return srcs


class Module:
    """
    Module represents a builder which builds a Makefile file.
    """

    def __init__(self, storage):
        self._ctx = Context(storage)
        self._protoc = "protoc"
        self._protos = set()
        self._proto_srcs = []
        self._artifacts = []
        self._phonies = ["all", "clean"]
        self._vars = self._adjust(
            {
                "cc": "gcc",
                "cxx": "g++",
                "protoc": "protoc",
                "ccache": "",
                "incs": [],
                "clfags": [],
                "cxxflags": [],
                "ldflags": [],
                "output": "output",
            }
        )

    def config(self, **kwargs):
        new_vars = {}
        for name in self._vars.keys():
            val = kwargs.get(name)
            if val is not None:
                new_vars[name] = val
        self._vars.update(self._adjust(new_vars))

    def output(self):
        return self._vars["output"]

    def set_protoc(self, name_or_path):
        self._protoc = name_or_path

    def proto_srcs(self):
        return self._proto_srcs

    def _adjust(self, kwargs):
        if "incs" in kwargs:
            kwargs["incs"] = Includes(globs(kwargs["incs"]))
        flags = kwargs.pop("ldflags", ())
        ldflags = Flags()
        ldlibs = LdLibs()
        for ldflag in flags:
            ldflag = ldflag.strip()
            if ldflag.startswith("-") and not ldflag.startswith("-l"):
                ldflags.append(ldflag)
            else:
                ldlibs.append(ldflag)
        kwargs["ldlibs"] = ldlibs
        kwargs["ldflags"] = ldflags
        for flags in ("cflags", "cxxflags"):
            if flags in kwargs:
                kwargs[flags] = Flags(kwargs[flags])
        return kwargs

    def _sanitize(self, srcs, deps, protos, kwargs):
        sources = globs(srcs)
        assert sources, "no matched files were found in: %s" % srcs
        protobufs = globs(protos)
        kwargs = {key: val for key, val in kwargs.items() if val}
        pbs = [proto.replace(".proto", ".pb.cc") for proto in protobufs]
        self._protos.update(protobufs)
        scope = Scope(self._adjust(kwargs))
        scope.extend(self._vars)
        return scope, sources + pbs, deps

    def _add_artifact(self, cls, name, srcs, deps, protos, kwargs):
        scope, srcs, deps = self._sanitize(srcs, deps, protos, kwargs)
        artifact = cls(self._ctx, name, scope, srcs, deps)
        self._ctx.define(name, deps)
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

    def artifacts(self):
        return self._artifacts

    def phonies(self):
        return self._phonies

    def build(self, makefile, name):
        assert name is None or self._ctx.is_defined(name), "unknown name: %s" % name
        for proto in self._protos:
            pbname, _ = os.path.splitext(proto)
            pbh, pbcc = pbname + ".pb.h", pbname + ".pb.cc"
            self._proto_srcs += (pbh, pbcc)
            if os.path.exists(pbh) and os.path.exists(pbcc):
                pbh_mtime = os.path.getmtime(pbh)
                pbcc_mtime = os.path.getmtime(pbcc)
                proto_mtime = os.path.getmtime(proto)
                if pbh_mtime > proto_mtime and pbcc_mtime > proto_mtime:
                    continue

            proto_dirs = set([os.path.dirname(path) for path in self._protos])
            proto_paths = " ".join(
                ["--proto_path " + proto_dir for proto_dir in proto_dirs]
            )
            command = "%s %s --cpp_out=%s %s" % (
                self._protoc,
                proto_paths,
                os.path.dirname(proto),
                proto,
            )
            say(command)
            ret, _, __ = subcall(command, sys.stdout)
            assert ret == 0

        artifacts = []
        for artifact in self._artifacts:
            if name is None or artifact.name() in [name] + self._ctx.get_deps(name):
                say("artifact: %s", artifact.name())
                artifact.build()
                # Collect filtered artifact by `name`.
                artifacts.append(artifact)
        self._artifacts = artifacts
        self._make(makefile)

    def _make(self, makefile):
        targets = set()
        names = []
        rules_list = []
        for artifact in self._artifacts:
            names.append(artifact.name())
            rules_list.append(artifact.rules())
            targets.update(artifact.targets())

        rules = []
        rules.append(MakeRule(".PHONY", self._phonies))
        rules.append("")
        rules.append(MakeRule("all", names))

        for r in rules_list:
            rules.append("")
            rules.append("")
            rules.extend(r)

        rules.append("")
        rules.append("")
        rules.append(CleanRule(sorted(targets)))

        for dirc in sorted((os.path.dirname(target) for target in targets)):
            if not os.path.exists(dirc):
                os.makedirs(dirc)

        self._write_to(rules, makefile)

    def _write_to(self, rules, makefile):
        notice = "\n".join(
            (
                "# file : Makefile",
                "# brief: this file was generated by `bukit`",
                "# date : %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            )
        )

        with open(makefile, "w") as out:
            out.write(notice)
            out.write("\n")
            out.write("\n")
            for rule in rules:
                out.write(str(rule))
                out.write("\n")

    def save(self):
        storage = self._ctx.storage()
        storage.set_output(self._vars["output"])
        storage.set_pbsrcs(self._proto_srcs)
        for artifact in self._artifacts:
            artifact.save()


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
        name,
        srcs=(),
        protos=(),
        deps=(),
        lib="",
        shared=False,
        prebuilt=False,
        **kwargs
    ):
        if prebuilt:
            assert len(srcs) == 1, "attr `srcs` size must be 1 in prebuilt library"
            module.add_prebuilt(name, srcs, kwargs)
        elif shared:
            module.add_shared(name, srcs, deps, protos, kwargs)
        else:
            assert not deps, "attr `deps` is not supported in static library"
            module.add_static(name, srcs, protos, kwargs)

    return dict(locals(), **{name.upper(): func for name, func in locals().items()})


class Template:
    """
    Build Template which generates a BUILD file.
    """

    def format(self, kwargs):
        kwargs.setdefault("name", "app")
        lines = [
            "config(",
            "    cflags=[",
            '        "-g",',
            '        "-O0",',
            '        "-std=c11",',
            '        "-pipe",',
            '        "-W",',
            '        "-Wall",',
            '        "-fPIC",',
            '        "-fno-omit-frame-pointer",',
            "    ],",
            "    cxxflags=[",
            '        "-g",',
            '        "-O0",',
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
            '    name="%(name)s",',
            '    incs=["src/"],',
            '    srcs=["src/*.cc", "src/*.cpp"],',
            ")",
        ]
        return "\n".join(lines) % kwargs


class Storage:
    """
    Load and store a shelve db, also compare with current cache.
    """

    def __init__(self, path):
        if not os.path.exists(path):
            os.mkdir(path)
        self._manifest_db = shelve.open(os.path.join(path, "manifest"))
        self._cache = {}
        self._target_db = shelve.open(os.path.join(path, "targets"))

    def path(self):
        return self._manifest_db["path"]

    def set_output(self, output_path):
        self._manifest_db["output_path"] = output_path

    def output(self):
        return self._manifest_db.get("output_path")

    def set_pbsrcs(self, pbsrcs):
        self._manifest_db["pbsrcs"] = pbsrcs

    def pbsrcs(self):
        return self._manifest_db.get("pbsrcs") or ()

    def put_artifact(self, name, target):
        self._manifest_db[name] = target

    def get_artifact(self, name):
        return self._manifest_db.get(name)

    def put_target(self, target, prereqs, command, is_obj):
        self._cache[target] = (prereqs, command, is_obj)

    def save(self):
        if self._target_db:
            self.compare()

        self._target_db.clear()
        self._target_db.update(self._cache)
        self._target_db.close()
        self._manifest_db.close()

    def compare(self):
        delete = lambda x: os.path.exists(x) and os.remove(x)
        # for target, (prereqs, command, _) in self._cache.items():
        #     old_prereqs, old_command, _ = self._target_db.get(target, [None] * 3)
        #     if prereqs != old_prereqs or command != old_command:
        #         delete(target)
        expired_keys = set(self._target_db.keys()) - set(self._cache.keys())
        for key in expired_keys:
            delete(key)
        for target, (prereqs, _, is_obj) in self._target_db.items():
            if is_obj:
                continue
            if set(prereqs) & expired_keys:
                delete(target)


class Bukit:
    """
    Collect all of rules and generate a makefile file.
    """

    def __init__(self):
        self._meta_path = ".bukit"
        self._storage = Storage(self._meta_path)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._storage.save()

    def _build(self, name=None):
        def execute(path, globals):
            with open(path) as f:
                code = compile(f.read(), path, "exec")
                exec(code, globals)

        workspace = os.getcwd()
        module = Module(self._storage)
        execute(os.path.join(workspace, "BUILD"), api(module))
        module.build("Makefile", name)
        module.save()

    def _make(self, target):
        target = target or "all"
        start = time.time()
        say("-" * 60)
        cmd = "make %s" % target
        say(cmd)
        ret, _, __ = subcall(cmd, sys.stdout)
        if ret == 0:
            end = time.time()
            say("make cost: %ss", int(end - start))
        say("-" * 60)

    def build(self, options):
        self._build(options.name)
        target = "all"
        self._make(options.name or "all")
        return target

    def run(self, options):
        say("run `%s`", options.name)
        target = self.build(options)
        ret, _, _ = subcall(target, sys.stdout)
        sys.exit(ret)

    def clean(self, options):
        say("clean ...")
        if options.clean:
            ret, _, __ = subcall("make clean", sys.stdout)
            assert ret == 0
        else:
            if self._storage.pbsrcs():
                for pb_name in self._storage.pbsrcs():
                    if os.path.exists(pb_name):
                        os.remove(pb_name)
            workspace = os.getcwd()
            makefile_path = os.path.join(workspace, "Makefile")
            meta_path = os.path.join(workspace, self._meta_path)
            if os.path.exists(makefile_path):
                os.remove(makefile_path)
            shutil.rmtree(meta_path, True)
            if self._storage.output():
                shutil.rmtree(self._storage.output(), True)
        say("clean done")

    def create(self, options):
        tpl = Template()
        content = tpl.format(options)
        with open("BUILD", "w") as f:
            f.write(content)
        say("the `BUILD` has been generated in the current directory", color="yellow")


def do_args(argv):
    name, args = argv[0], argv[1:]
    parser = ArgumentParser(os.path.basename(name), version=__version__)
    create_parser = OptionsParser()
    create_parser.add_option("--name", help="Artifact name. eg: app", default="app")
    build_parser = OptionsParser()
    build_parser.add_option("--name", help="Build and make ${name}")
    run_parser = OptionsParser()
    run_parser.add_option("--name", help="Execute ${name}", required=True)
    clean_parser = OptionsParser()
    clean_parser.add_option(
        "--clean", help="Only execute command: make clean", typo="bool"
    )
    parser.add_command("create", "Create BUILD file", create_parser)
    parser.add_command("build", "Build project and generate a makefile", build_parser)
    parser.add_command("run", "Execute ${target}", run_parser)
    parser.add_command("clean", "Clean this project", clean_parser)
    command, options = parser.parse(args)
    return command, options


def main():
    say(LOGO)
    command, options = do_args(sys.argv)
    with Bukit() as bukit:
        if command == "create":
            bukit.create(options)
        elif command == "build":
            bukit.build(options)
        elif command == "run":
            bukit.run(options)
        elif command == "clean":
            bukit.clean(options)


if __name__ == "__main__":
    main()
