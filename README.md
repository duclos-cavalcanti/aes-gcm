# AES-GCM

A modularized AES 128 bit implementation using the Galois Counter mode. Specifications can be seen in the `docs` folder. Tests
to their individual correctness can be seen in the `main.c` file commented out.

```sh
.
├── bin
├── build
├── cmake
├── CMakeLists.txt
├── compile_commands.json -> build/compile_commands.json
├── docs
├── include
├── lib
├── LICENSE
├── README.md
└── src
```

The source files can be found in `src`, include files in `include` and cmake scripts in `cmake`. Running **make** in from
within the build folder will generate a binary in the `bin` folder. To run said program, either call it directly or
run the `make run` target. There is also a `make debug` target that can enable one to debug the compiled binary with
gdb if installed in one's system.
