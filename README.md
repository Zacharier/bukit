# Bukit

The Bukit(**Bu**ild **Kit**) is a simple but powerful build tool for C/C++ project. 

By executing a `BUILD` file, the Bukit can deductions relationships of dependency between source files and generates a `Makefile` file. In addtion, it can also watchs all file changes(eg: files are updated/deleted or add new one) and re-generate a new `Makefile`. The generated `Makefile` can be "maked" manually or automatically after the build is complete. 

## Installing
Install and update using pip:
```
pip install -U git+https://github.com/Zacharier/bukit.git
```
or
```
git clone https://github.com/Zacharier/bukit.git
cd bukit
pip install .
```

## How to use

### Create
First, make sure to be in the **root directory** of the project.


A simplest method to create a `BUILD` if you have only source file:

```shell
echo "binary('app', ['main.cc'])" > BUILD
```

Another method to create a `BUILD` is automatic generation from a built-in template, eg:

```shell
bukit create
```

Finally, a `BUILD` file was generated and placed to current directory.

### Build
Execute `Build` to build project:
```Shell
bukit build
```

The `Makefile` was generated during the command is executing, and next the `make` command was automatically executed. Finally, a binary or library file was built and placed into `output` directory.

### Clean
Clean object files and others Intermediate temporary file:

```Shell
bukit clean
```

more examples can see in [examples](examples).

## Contribute

## Bug Report

