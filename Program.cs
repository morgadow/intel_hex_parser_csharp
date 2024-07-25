
using Libraries.IntelHexParser;
using System.Collections;
using System.Text;


const string hexfile = "./hexfile.hex";
const string binfile = "./binfile.bin";


Serializer serializer = new Serializer();
byte[] output = serializer.Deserialize(hexfile);


using (var writer = new StreamWriter(binfile, false, Encoding.UTF8))
{
    foreach (var b in output)
    {
        writer.WriteLine(b);
    }
}
