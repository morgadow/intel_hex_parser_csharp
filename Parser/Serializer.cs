using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using static System.Runtime.InteropServices.JavaScript.JSType;


/* Note:
All used HEX files are formatted as Intel HEX files.
As only those file formats are used, all further specification can be assumed to be for Intel HEX format.

Base for this implementation was following wikipedia site:
https://en.wikipedia.org/wiki/Intel_HEX
*/


namespace Libraries.IntelHexParser
{
    public class Serializer
    {
        private const int StartCodeOffset = 0;
        private const int StartCodeLength = 1;
        private const int ByteCountOffset = StartCodeOffset + StartCodeLength;
        private const int ByteCountLength = 2;
        private const int AddressOffset = ByteCountOffset + ByteCountLength;
        private const int AddressLength = 4;
        private const int RecordTypeOffset = AddressOffset + AddressLength;
        private const int RecordTypeLength = 2;
        private const int DataOffset = RecordTypeOffset + RecordTypeLength;
        private const int ChecksumLength = 2;
        
        private const int MinimalLineLength = StartCodeLength + ByteCountLength + AddressLength + RecordTypeLength + ChecksumLength;

        // <summary>
        // Deserializes an Intel Hex file into an binary array
        // </summary>
        public byte[] Deserialize(string filePath)
        {
            string source = loadFileContent(filePath);
            return parseHexFile(source);
        }

        /// <summary>
        /// Parse the content of an intel hex file into a binary array
        /// </summary>
        private byte[] parseHexFile(string source)
        {
            string[] lines = source.Split(Environment.NewLine.ToCharArray());
            lines = lines.Where(line => line.Length > 0).ToArray();
            int recordIndex = 0;
            int finalDataSize = 0;

            // parse line by line into an record and save all records in array
            Record record;
            Record[] records = new Record[lines.Length];
            int segmentAddress = 0, maxAddress = 0, tmp;
            foreach (string l in lines)
            {
                record = parseLine(l);
                records[recordIndex++] = record;
                finalDataSize += record.DataLength;

                /* Evaluate the final data size based on the record addresses. 
                 TODO This is badly implemented and can be fixed to be more robust*/
                switch (record.Type)
                {
                    case RecordType.ExtendedSegmentAddress:
                    case RecordType.StartSegmentAddress:
                        segmentAddress = (record.Data[0] << 8 | record.Data[1]);
                        segmentAddress <<= 4;
                        break;
                    case RecordType.ExtendedLinearAddress:
                        segmentAddress = (record.Data[0] << 8 | record.Data[1]);
                        segmentAddress <<= 16;
                        break;
                }
                tmp = segmentAddress + record.Address + record.DataLength;
                if (tmp > maxAddress) { maxAddress = tmp; };
            }
            finalDataSize = maxAddress;

            // concatenate all data into a single array using the addresses and data of each record
            segmentAddress = 0;
            bool endReached = false;
            byte[] outcome = new byte[finalDataSize];
            foreach (Record r in records)
            {
                if (endReached) { break; }

                switch (r.Type)
                {
                    case RecordType.Data:
                        updateBinaryArray(r, segmentAddress, ref outcome);
                        break;
                    case RecordType.EndOfFile:
                        endReached = true;
                        break;
                    case RecordType.ExtendedSegmentAddress:
                        segmentAddress = (r.Data[0] << 8 | r.Data[1]);
                        segmentAddress <<= 4;
                        break;
                    case RecordType.StartSegmentAddress:
                        segmentAddress = (r.Data[0] << 8 | r.Data[1]);
                        segmentAddress <<= 4;
                        break;
                    case RecordType.ExtendedLinearAddress:
                        segmentAddress = (r.Data[0] << 8 | r.Data[1]);
                        segmentAddress <<= 16;
                        break;
                    case RecordType.StartLinearAddress:
                        throw new Exception("Record type 'StartLinearAddress' (0x05) not supported!");
                    default:
                        throw new Exception(string.Format("Record type {0} not supported!", r.Type));
                }
            }

            return outcome;
        }

        // <summary>
        // Load the content of an intel hex file into a binary array
        // </summary>
        private string loadFileContent(string filePath)
        {
            // check file is actually a hex file
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("Could not find file: {}", filePath);
            if (!Path.GetExtension(filePath).Equals(".hex", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("File is not a hex file: {}", filePath);

            return File.ReadAllText(filePath);
        }

        /// <summary>
        /// Parse a single line into a record
        /// Throws an exception if the line is invalid
        /// </summary>
        private Record parseLine(string line)
        {
            Record record = new Record();

            if (line.Length < MinimalLineLength)
                throw new Exception(string.Format("Line is short as the minimum line length of {0}: {1}", MinimalLineLength, line));
            if (line[StartCodeOffset] != Record.StartCode)
                throw new Exception(string.Format("Line does not start with the start code of {0}: {1}", Record.StartCode, line));

            record.DataLength = Convert.ToUInt16(line.Substring(ByteCountOffset, ByteCountLength), 16); // TODO war parse to int
            record.Address = Convert.ToUInt16(line.Substring(AddressOffset, AddressLength), 16);
            record.Type = (RecordType)Convert.ToInt16(line.Substring(RecordTypeOffset, RecordTypeLength), 16);
            record.Data = new byte[record.DataLength];
            for (int i = 0; i < record.DataLength; i++)
            {
                record.Data[i] = Convert.ToByte(line.Substring(DataOffset + 2 * i, 2), 16);
            }

            if (!IsChecksumValid(line, record))
                throw new Exception(string.Format ("Checksum is invalid: {0}", line));
            if (!IsRecordValid(record.Type))
                throw new Exception(string.Format("Record type {0} not supported!", record.Type.ToString()));

            return record;
        }

        /// <summary>
        /// Check if the checksum of a record is valid
        /// </summary>
        private bool IsChecksumValid(string line, Record record)
        {
            byte current = Convert.ToByte(line.Substring(DataOffset + record.DataLength * 2, ChecksumLength), 16);
            return record.Checksum == current;
        }

        /// <summary>
        /// Check if a record type is valid for this kind of files
        /// </summary>
        private bool IsRecordValid(RecordType type)
        {
            return (type != RecordType.Data ||
                type != RecordType.EndOfFile ||
                type != RecordType.ExtendedLinearAddress ||
                type != RecordType.ExtendedSegmentAddress ||
                type != RecordType.StartLinearAddress ||
                type != RecordType.StartSegmentAddress);
        }

        /// <summary>
        /// Update the binary array with the data of a record
        /// The final position in the array is determined by the address and the offset given by the ExtendedSegmentAddressRecord
        /// </summary>
        private void updateBinaryArray(Record record, int segmentAddr, ref byte[] binArray)
        {
            for (int i = 0; i < record.DataLength; i++)
            {
                var index = i + record.Address + segmentAddr;
                if (index >= binArray.Length)
                {
                    throw new Exception("Binary array is too small, needed at least " + index + " bytes, have " + binArray.Length + " bytes!");
                }

                binArray[index] = record.Data[i];
            }
        }
    }
}