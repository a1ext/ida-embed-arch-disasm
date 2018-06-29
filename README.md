IDA Embed arch disasm
---------------------

Allows you to disassemble x86-64 code (like inlined WOW64 one) while you using 32-bit IDA database. This would be helpfull to analyze WOW64 mode switches.

## Dependencies

* `capstone` Python module

In case you use IDA 7 and newer make sure you download and install `capstone` for appropriate Python version and architecture, because since IDA 7 by default is 64-bit. You could find the binary installer [here](https://www.capstone-engine.org/download.html)

## Showcase

### Before

![before0.png](docs/before0.png)


### Select the range you want to disassemble

![open_menu0.png](docs/open_menu0.png)

### After (disassembled instructions are in comments)

![after0.png](docs/after0.png)



