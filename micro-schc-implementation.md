# MicroSCHC implementation

**brief**: This document keeps track of choices made during the implementation of microSCHC.

## 1. Parser

Instead of relying on an external parser, e.g. Scapy [1], microSCHC includes its own parser.
This choice is motivated by constraints on the memory footprint, code size and library availability
of the targeted run environment, i.e. microPython. This is further motivated by design choices made
in [section 1.2](#on-interpretation-vs-decoding-vs-parsing), in particular the decision to **not** interpret
fields of headers.

### 1.1. Types Support

Discussed extensively in issue [#1](https://github.com/quentinlampin/microschc/issues/1), microSCHC only support basic types, i.e. bytes and integers.

### 1.2 On interpretation vs decoding vs parsing


- [1] "Scapy, packet crafting for Python2 and Python3"
