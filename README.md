# Intel Hex File Parser

This project is a parser for the Intel hex file format.
It aims to load .hex files and export them to a binary array ready for download to a controller.

> Note: This project can be used without restrictions, I would just appreciate any comments that you use it for your projects :)

## General

The input file is loaded and deserialised into a byte array. \
The total size of the output byte array corresponds to the maximum reserved address space specified in the hex file. \
Empty spaces between the reserved sections in the hex file are automatically filled by the *defaultValue* parameter, which is set to 0xff by default. \
The output binary array can be downloaded / flashed to a controller or saved in a .bin file as shown in the example below.

> Note: During deserialisation, this package uses the built-in checksums in each line of the .hex file to check if the data is corrupted.

## Example

The following example shows the usage of the package.

```c#
using IntelHexParser;
using System.Collections;
using System.Text;

// input and output files
const string hexfile = "C:/workspace/intel_hex_parser_csharp/hexfile.hex";
const string binfile = "C:/workspace/intel_hex_parser_csharp/binfile.bin";

// deserialize hex file
Serializer serializer = new Serializer();
byte defaultValue = 0xff;
byte[] output = serializer.Deserialize(hexfile, defaultValue);

// write to binary file
File.WriteAllLines(binfile, output.Select(b => b.ToString()));
```

## Known Issues

- The output binary might be a little larger than the biggest address space in the .hex file would require it to be.
As the FLASH space is normally not utilized by exactly 100%, there should be this extra available space and therefore no problem.
- The usage of the identifier "Start Linear Address Records" is currently not implemented as it was never used in any projects I encountered.
To anyone willing to update this, please feel free to raise a merge request adding this missing functionality.
