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
    name="foo",
    incs=["src"],
    srcs=[
        "src/foo.cc",
    ],
)

library(
    name="bar",
    incs=["src"],
    srcs=[
        "src/bar.cc",
    ],
    shared=True,
)

# library(
#     name="base",
#     srcs=[
#         "output/lib",
#     ],
#     prebuilt = True,
# )

binary(
    name="app",
    incs=["src/"],
    srcs=[
        "src/main.cc",
    ],
    ldflags=[
        "-Wl,-rpath=output/lib",
    ],
    deps=[
        "foo",
        "bar",
        # "base",
    ],
)
