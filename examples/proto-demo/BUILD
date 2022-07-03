config(
    cflags=[
        "-g",
        "-pipe",
        "-W",
        "-Wall",
        "-fPIC",
        "-std=c99",
        "-O0",
        "-fno-omit-frame-pointer",
    ],
    cxxflags=[
        "-g",
        "-pipe",
        "-W",
        "-Wall",
        "-fPIC",
        "-std=c++11",
        "-O0",
        "-fno-omit-frame-pointer",
    ],
    ldflags=["-L/usr/local/lib"],
)

library(
    name="pbs",
    protos=["protos/*.proto"],
    shared=True,
)

binary(
    name="app",
    incs=["./", "src/"],
    srcs=["src/*.cc", "src/*.cpp"],
    deps=["pbs"],
    ldflags=["-lprotobuf"],
)
