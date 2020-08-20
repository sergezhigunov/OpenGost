using System;
using System.Security.Cryptography;
using System.Text;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    internal static class AsnUtils
    {
        internal static byte[] DecodeOctetString(AsnEncodedData encodedData)
        {
            if (encodedData == null)
                throw new ArgumentNullException(nameof(encodedData));

            var rawData = encodedData.RawData;
            var position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.OctetString)
                throw new InvalidOperationException();

            var length = ReadLength(rawData, ref position);
            var result = new byte[length];
            Buffer.BlockCopy(rawData, position, result, 0, length);
            return result;
        }

        internal static AsnEncodedDataCollection DecodeSequence(AsnEncodedData encodedData)
        {
            if (encodedData == null)
                throw new ArgumentNullException(nameof(encodedData));

            var rawData = encodedData.RawData;
            var position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.Sequence)
                throw new InvalidOperationException();

            var end = position + ReadLength(rawData, ref position);

            var result = new AsnEncodedDataCollection();
            while (position < end)
                result.Add(new AsnEncodedData(ReadTriplet(rawData, ref position)));

            return result;
        }

        internal static string DecodeOidValue(AsnEncodedData encodedData)
        {
            if (encodedData == null)
                throw new ArgumentNullException(nameof(encodedData));

            var rawData = encodedData.RawData;
            var position = 0;
            if (ReadTag(rawData, ref position) != AsnTag.ObjectIdentifier)
                throw new InvalidOperationException();

            var end = position + ReadLength(rawData, ref position);
            var stringBuilder = new StringBuilder();
            var firstByte = ReadByte(rawData, ref position);
            stringBuilder.Append(firstByte / 40).Append('.').Append(firstByte % 40);
            while (position <= end)
            {
                var value = 0;
                byte b;
                do
                {
                    b = ReadByte(rawData, ref position);
                    value *= 128;
                    value += b % 128;
                }
                while (b >= 128);
                stringBuilder.Append('.').Append(value);
            }
            return stringBuilder.ToString();
        }

        internal static AsnTag GetAsnTag(AsnEncodedData encodedData)
        {
            if (encodedData == null)
                throw new ArgumentNullException(nameof(encodedData));

            var position = 0;
            return ReadTag(encodedData.RawData, ref position);
        }

        private static byte[] ReadTriplet(byte[] rawData, ref int position)
        {
            var start = position;
            ReadTag(rawData, ref position);
            var length = ReadLength(rawData, ref position);
            position += length;
            var result = new byte[position - start];
            Buffer.BlockCopy(rawData, start, result, 0, position - start);
            return result;
        }

        private static AsnTag ReadTag(byte[] rawData, ref int position)
            => (AsnTag)ReadByte(rawData, ref position);

        private static byte ReadByte(byte[] rawData, ref int position)
            => rawData[position++];

        private static int ReadLength(byte[] rawData, ref int position)
        {
            int length;
            var lengthByte = rawData[position++];
            if (lengthByte < 0x80)
                length = lengthByte;
            else
            {
                lengthByte ^= 0x80;
                length = ReadByte(rawData, ref position);

                for (var i = 1; i < lengthByte; i++)
                    length = (length << 8) + ReadByte(rawData, ref position);
            }

            return length;
        }

    }
}
