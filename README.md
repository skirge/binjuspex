# Pseudo C Dump (v1.1)
Author: **Asher Davila L.**

_Binary Ninja plugin to dump the Pseudo C generated by Binja into a folder._

This version adds some improvements from semgrep plugin but still dumps functions into individual C files for offline analysis
with semgrep or other tool.
tree-sitter-c needs to be added as submodule into plugin directory

```
cd binjuspex
git clone https://github.com/tree-sitter/tree-sitter-c
```

## Description:

This Binary Ninja plugin is written in Python 3 and it aims to assist with reverse engineering  and vulnerability research. It dumps the Pseudo C representation of a binary, generated by Binja's decompiler, into a specified folder. 

Even though Binja has a built-in File -> Export option, it saves the output into a single file and contains extra information such as Segments, Sections, memory addresses, and other information that might not be necessary, depending on the intended use of the generated output.

The motivation for writing this plugin is to extract the Pseudo C representation of a binary in a format that can be easily imported into an IDE, or parsed by static analysis tools like [Semgrep](https://github.com/returntocorp/semgrep).

PCDump-bn plugin is inspired by [atxsinn3r](https://github.com/atxsinn3r)'s Binja plugin, [BinjaHLILDump](https://github.com/atxsinn3r/BinjaHLILDump), which dumps the HLIL, and by [0xdea](https://github.com/0xdea) Ghidra's [plugin](https://github.com/0xdea/ghidra-scripts/blob/main/Haruspex.java), which dumps the pseudo-code generated by the Ghidra decompiler.


## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3814

## Contributing

Any feedback and any help from external maintainers are appreciated.

* Create an [issue](https://github.com/AsherDLL/PCDump-bn/issues) for feature requests or bugs that you have found.

* Submit a pull request for fixes and enhancements for this tool.

## License

This plugin is released under an [Apache 2.0 License](./LICENSE).
