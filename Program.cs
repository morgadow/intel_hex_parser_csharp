
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
