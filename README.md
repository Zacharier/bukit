# Bukit

The Bukit(**Bu**ild **Kit**) is a simple but powerful build tool for C/C++ project. 

By executing a `BUILD` file, the Bukit can deductions relationships of dependency between source files and generates a `Makefile` file. In addtion, it can also watchs all file changes(eg: files are updated/deleted or add new one) and re-generate a new `Makefile`. The generated `Makefile` can be "maked" manually or automatically after the build is complete. 

## Installing
Install and update using pip:
```shell
$ pip install -U git+https://github.com/Zacharier/bukit.git
```
or
```shell
git clone https://github.com/Zacharier/bukit.git
cd bukit
pip install .
```
## A Simple Example
```shell
$ bukit create
```
```c++
// save this as main.cc or any name ended with .cc/.cpp
#include <iostream>

int main() {
    std::cout << "Hello, World" << std::endl;
    return 0;
}
```
```shell
$ bukit run
Hello, World
```

## How to use

### Create
First, make sure to be in the **root directory** of the project.


A simplest method to create a `BUILD` if you have only source file:

```shell
echo "binary('app', ['main.cc'])" > BUILD
```

Another method to create a `BUILD` is automatic generation from a built-in template:

```shell
bukit create [--name <NAME>]
```

The `NAME` in the arguments represent the name of artifact(a binary or library) and default to `app` if `--name` was not set.

After the above command is completed, a `BUILD` file was generated and placed to current directory.

### Build
Execute `Build` to build project:
```Shell
bukit build [--name <NAME>]
```

The `Makefile` was generated during the command is executing, and next the `make` command was automatically executed. Finally, the artifacts (some binaries or libraries) were built and placed into `output` directory.

**NOTE**: Only build a specific artifact if `--name` was set, otherwise all artifacts will be built.

### Run

Execute the artifact by specifying a name:
```Shell
bukit run [--name <NAME>]
```

The Bukit queries artifact by `NAME` and run it.

All artifacts will be return if `--name` was not set. If there is only one executable artifact return by query, this artifact will be run. Otherwise a error will be raised because which will be run is ambiguous, in this case, a `NAME` should be specified explicitly.

**NOTE**: Build first if it hasn't been built yet.
### Clean
Clean object files and others Intermediate temporary file:

```Shell
bukit clean
```

more examples can see in [examples](examples).

## Contribute

## Bug Report

