config(
    cflags=[
        "-g",
        "-O0",
        "-std=c11",
        "-pipe",
        "-W",
        "-Wall",
        "-fPIC",
        "-fno-omit-frame-pointer",
    ],
    cxxflags=[
        "-g",
        "-O0",
        "-std=c++11",
        "-pipe",
        "-W",
        "-Wall",
        "-fPIC",
        "-fno-omit-frame-pointer",
    ],
    ldflags=["-L/usr/local/lib"],
)


binary(
    name="app",
    incs=["src/"],
    srcs=["src/*.cc", "src/*.cpp"],
)