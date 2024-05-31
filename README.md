![](https://raw.githubusercontent.com/cla7aye15I4nd/cla7aye15i4nd.github.io/main/static/usenixbadges-available.png)
![](https://raw.githubusercontent.com/cla7aye15I4nd/cla7aye15i4nd.github.io/main/static/usenixbadges-functional.png)
![](https://raw.githubusercontent.com/cla7aye15I4nd/cla7aye15i4nd.github.io/main/static/usenixbadges-reproduced.png)

# CAMP: Compiler and Allocator-based Heap Memory Protection

## Overview

CAMP is a new sanitizer for detecting and capturing heap memory corruption. CAMP leverages a compiler and a customized memory allocator. The compiler adds boundary-checking and escape-tracking instructions to the target program, while the memory allocator tracks memory ranges, coordinates with the instrumentation, and neutralizes dangling pointers. With the novel error detection scheme, CAMP enables various compiler optimization strategies and thus eliminates redundant and unnecessary check instrumentation.


[CAMP's allocator](https://github.com/Markakd/safe_tcmalloc) is built on tcmalloc. Users can use `python3 menuconfig.py` to modify the behavior when the allocator detects an error.

CAMP has modified tcmalloc, with the most significant changes being in the cache design and the addition of a checking function. These modifications can be found at https://github.com/Markakd/safe_tcmalloc/blob/main/tcmalloc/tcmalloc.cc.

[CAMP's compiler](src/compiler_pass) is built on top of the LLVM12 compiler framework. We implement the instrumentation and optimization within an LLVM pass, loadable by Clang. To defend against heap overflow, it instruments all pointer arithmetic and type-casting instructions. Users can enable or disable specific optimizations or checks by changing the value in [config.h](src/compiler_pass/config.h).

For each optimization's implementation, we point out its location in the code:
- Optimizing range checks with type information [src](src/compiler_pass/Protection.cpp#L548)
- Removing Redundant Instructions [src](src/compiler_pass/Protection.cpp#L993)
- Merging Runtime Calls [src](src/compiler_pass/Protection.cpp#L980)

## Prerequisite

Before beginning the installation and setup process, ensure that your system meets the following requirements:
- Ubuntu 22.04: This software is designed to run on Ubuntu 22.04, ensuring compatibility and smooth operation.
- Clang 12.0.1: Clang, a compiler for the C family of programming languages, is required at version 12.0.1 to compile and run this software efficiently.

## Build

To install CAMP on your system, follow these steps:
```bash
git clone https://github.com/cla7aye15I4nd/CAMP.git
cd CAMP
git submodule update --init --recursive
cd src/safe_tcmalloc && python3 menuconfig.py
mkdir build && cd build 
cmake .. && make 
```
These commands clone the repository, set up necessary submodules, configure settings, and compile the project, preparing it for use.

## Usage

To use the CAMP tools, run the following commands:
```bash
tools/vcc <compile options>  # Use vcc tool with specified compile options
tools/v++ <compile options>  # Use v++ tool with specified compile options
```
These commands allow you to utilize the `vcc` and `v++` tools included with CAMP, enabling you to compile your projects with the specific options you need.

## Experiments

[CAMP Experiment](https://github.com/cla7aye15I4nd/camp-experiment) include all documents and scripts that we used in evaluation and artfact.

## Bibtex
```
@inproceedings{lin2024camp,
    title = {{CAMP}: Compiler and Allocator-based Heap Memory Protection},
    author={Lin, Zhenpeng and Yu, Zheng and Guo, Ziyi and Campanoni, Simone and Dinda, Peter and Xing, Xinyu},
    booktitle = {33rd USENIX Security Symposium (USENIX Security 24)},
    year = {2024},
}
```
