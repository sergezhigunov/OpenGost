using System;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    using System.Text;
    using static Buffer;

    internal static class AsnUtils
    {
        internal static byte[] DecodeOctetString(AsnEncodedData encodedData)
        {
            if (encodedData == null) throw new ArgumentNullException(nameof(encodedData));

            byte[] rawData = encodedData.RawData;
            int position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.OctetString)
                throw new InvalidOperationException();

            int length = ReadLength(rawData, ref position);
            byte[] result = new byte[length];
            BlockCopy(rawData, position, result, 0, length);
            return result;
        }

        internal static AsnEncodedDataCollection DecodeSequence(AsnEncodedData encodedData)
        {
            if (encodedData == null) throw new ArgumentNullException(nameof(encodedData));

            byte[] rawData = encodedData.RawData;
            int position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.Sequence)
                throw new InvalidOperationException();

            int end = position + ReadLength(rawData, ref position);

            var result = new AsnEncodedDataCollection();
            while (position < end)
                result.Add(new AsnEncodedData(ReadTriplet(rawData, ref position)));

            return result;
        }

        internal static string DecodeOidValue(AsnEncodedData encodedData)
        {
            if (encodedData == null) throw new ArgumentNullException(nameof(encodedData));

            byte[] rawData = encodedData.RawData;
            int position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.ObjectIdentifier)
                throw new InvalidOperationException();

            int end = position + ReadLength(rawData, ref position);
            var stringBuilder = new StringBuilder();
            byte firstByte = ReadByte(rawData, ref position);
            stringBuilder.Append(firstByte / 40).Append(".").Append(firstByte % 40);
            while (position <= end)
            {
                int value = 0;
                byte b;
                do
                {
                    b = ReadByte(rawData, ref position);
                    value *= 128;
                    value += b % 128;
                }
                while (b >= 128);
                stringBuilder.Append(".").Append(value);
            }
            return stringBuilder.ToString();
        }

        internal static AsnTag GetAsnTag(AsnEncodedData encodedData)
        {
            if (encodedData == null) throw new ArgumentNullException(nameof(encodedData));

            int position = 0;
            return ReadTag(encodedData.RawData, ref position);
        }

        private static byte[] ReadTriplet(byte[] rawData, ref int position)
        {
            int start = position;
            ReadTag(rawData, ref position);
            int length = ReadLength(rawData, ref position);
            position += length;
            byte[] result = new byte[position - start];
            BlockCopy(rawData, start, result, 0, position - start);
            return result;
        }

        private static AsnTag ReadTag(byte[] rawData, ref int position)
            => (AsnTag)ReadByte(rawData, ref position);

        private static byte ReadByte(byte[] rawData, ref int position)
            => rawData[position++];

        private static int ReadLength(byte[] rawData, ref int position)
        {
            int length;
            byte lengthByte = rawData[position++];
            if (lengthByte < 0x80)
                length = lengthByte;
            else
            {
                lengthByte ^= 0x80;
                length = ReadByte(rawData, ref position);

                for (int i = 1; i < lengthByte; i++)
                    length = (length << 8) + ReadByte(rawData, ref position);
            }

            return length;
        }

    }
}
