using System;
using System.Runtime.CompilerServices;

namespace Libraries.IntelHexParser
{
    /// <summary>
    /// Intel Hex Record types
    /// </summary>
    internal enum RecordType
    {
        Data                    = 0,
        EndOfFile               = 1,  
        ExtendedSegmentAddress  = 2,
        StartSegmentAddress     = 3,
        ExtendedLinearAddress   = 4,
        StartLinearAddress      = 5
    }

    /// <summary>
    /// Represents an basic Record in an Intel Hex file
    /// Basic record type (0x01)
    /// </summary>
    internal class Record
    {
        internal const char StartCode = ':';      // always the same at line start 

        internal RecordType Type { get; set; }
        internal ushort Address { get; set; }       // also called LoadOffset in Intel Hex spec
        internal int DataLength { get; set; }       // amount of data bytes
        internal byte[] Data { get; set; }
        internal byte Checksum
        {
            get
            {
                byte checksum;

                checksum = (byte)DataLength;
                checksum += (byte)Type;
                checksum += (byte)Address;
                checksum += (byte)((Address & 0xFF00) >> 8);

                for (int i = 0; i < DataLength; i++)
                {
                    checksum += Data[i];
                }

                checksum = (byte)(~checksum + 1);
                return checksum;
            }
        }

        public override string ToString()
        {
            string outcome;

            // store in little endian, show in big endian
            byte[] addressBytes = BitConverter.GetBytes(Address);
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(addressBytes);

            outcome = String.Format("{0}{1:X2}{2:X2}{3:X2}{4:X2}", StartCode, DataLength, addressBytes[0], addressBytes[1], Type);

            for (int i = 0; i < DataLength; i++)
            {
                outcome += String.Format("{0:X2}", Data[i]);
            }

            outcome += String.Format("{0:X2}", Checksum);
            return outcome;
        }
    }

    /* 
    /// <summary>
    /// Represents an End of File Record (0x01) in an Intel Hex file
    /// </summary>
    internal class EndOfFileRecord : Record
    {

    }

    /// <summary>
    /// Represents an Extended Segment Address Record (0x02) in an Intel Hex file
    /// </summary>
    internal class ExtendedSegmentAddressRecord : Record
    {
        internal ushort LoadOffset { get; set; }
    }

    /// <summary>
    /// Represents a Start Segment Address Record (0x03) in an Intel Hex file
    /// </summary>
    internal class StartSegmentAddressRecord : Record       // TODO needed?
    {
        internal ushort Segment { get; set; }
        internal ushort Offset { get; set; }
    }

    internal class ExtendedLinearAddressRecord : Record     // TODO needed?
    {
        internal uint LoadOffset { get; set; }
    }
    */
}