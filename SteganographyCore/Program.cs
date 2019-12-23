using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Drawing;

namespace Steganography
{
    class Program
    {
        private static string Usage = "Usage\n=====\n\n" +
            "  Decode\n  ¨¨¨¨¨¨\n" +
            "\t/d [image] (/p [password]) (/b [LSB]) (/i)\n" +
            "\n" +
            "  Encode\n  ¨¨¨¨¨¨\n" +
            "\t/e [image] [data] [output] (/f) (/p [password]) (/b [LSB]) (/i)\n" +
            "\n" +
            "  Descriptions\n  ¨¨¨¨¨¨¨¨¨¨¨¨\n" +
            "\timage\t- The image to use as source\n" +
            "\tdata\t- The message to encode within the [image] OR a filepath, if so, use the flag /f\n" +
            "\toutput\t- The encoded image path\n" +
            "\tLSB\t- How many least significan bits to use, must be 1, 2, 4 or 8 (default: 2)\n" +
            "\tpassword\t- Password to use when decoding/encoding (default: none)\n" +
            "\n" +
            "  Flags\n  ¨¨¨¨¨\n" +
            "\t/i\t- Turn on info/debug mode\n" +
            "\t/f\t- Interpret data as file (default: interpret as text message)\n" +
            "\tAdd all other flags here as well...\n" +
            "";
        private static Encoding BitEncoding = Encoding.Unicode;
        private static byte[] EndOfDataStreamSequense = new byte[] { 4, 0, 4, 0, 4, 0, 4 };
        private enum EmbeddedDataType
        {
            Unknown,
            Message,
            File        // Then the message is the filename
        }
        // Changing variables
        private static bool ShowDebugInfo;

        static void Main(string[] args)
        {
            //args = new string[] { "/e", "cat.jpg", "BBC123", "cat_enc.png", "/b", "4", "/p", "William Rågstad", "/i" };
            //args = new string[] { "/d", "cat_enc.png", "/b", "4", "/p", "William Rågstad", "/i" };

            //args = new string[] { "/e", "cat.jpg", "secret message.txt", "cat_file.png", "/f", "/b", "4", "/p", "William Rågstad", "/i" };
            //args = new string[] { "/d", "cat_file.png", "/b", "4", "/p", "William Rågstad", "/i" };

            //args = new string[] { "/e", "husky.png", "cat.jpg", "husky_cat.png", "/f" };
            //args = new string[] { "/d", "husky_cat.png" };
            
            Arguments a = Arguments.Parse(args);

            ShowDebugInfo = a.ContainsPattern("i");

            string password = null;
            if (a.ContainsPattern("p", typeof(string))) password = a["p"][0];

            int bitsEncoded = 2;
            int b = -1;
            if (a.ContainsPattern("b", typeof(int))) b = int.Parse(a["b"][0]);
            if (b > 0 && 8 % b == 0) bitsEncoded = b;

            if (a.ContainsPattern("e", typeof(string), typeof(string), typeof(string)))
            {
                // Check for /f
                bool dataIsFile = a.ContainsPattern("f");

                string[] p = a["e"];

                Bitmap image = getImage(p);
                if (image == null) return;

                string data = p[1];
                string output = p[2];

                if (dataIsFile)
                {
                    // Data is file
                    if (!File.Exists(data))
                    {
                        Console.WriteLine("Error! Data must be a valid filepath! (Don't use /f for messages)");
                        return;
                    }

                    if (ShowDebugInfo && password != null) Console.WriteLine($"Encrypting filename with password: \"{password}\"...");
                    byte[] encryptedName = Encrypt(BitEncoding.GetBytes(data), password);

                    if (ShowDebugInfo && password != null) Console.WriteLine($"Encrypting file binary with password: \"{password}\"...");

                    //string fileContent = File.ReadAllText(data);
                    //byte[] fileData = BitEncoding.GetBytes(fileContent);
                    byte[] fileData = File.ReadAllBytes(data);
                    byte[] encryptedData = Encrypt(fileData, password);

                    if (ShowDebugInfo) Console.WriteLine($"Encoding encrypted data into \"{p[0]}\"...");
                    
                    EncodeFile(image, encryptedName, encryptedData, output, bitsEncoded);
                }
                else
                {
                    // Data is message
                    byte[] messageBytes = BitEncoding.GetBytes(data);
                    byte[] encryptedMessage = Encrypt(messageBytes, password);
                    if (ShowDebugInfo && password != null) Console.WriteLine($"Encrypted: \"{data}\" with password: \"{password}\"");

                    if (ShowDebugInfo) Console.WriteLine($"Encoding encrypted message into \"{p[0]}\"...");

                    EncodeMessage(image, encryptedMessage, output, bitsEncoded);
                }
                if (ShowDebugInfo) Console.WriteLine($"Writing to file \"{output}\"...");
                if (ShowDebugInfo) Console.WriteLine("Done!");
            }
            else if (a.ContainsPattern("d", typeof(string)))
            {
                string[] p = a["d"];

                Bitmap image = getImage(p);
                if (image == null) return;

                if (ShowDebugInfo) Console.WriteLine($"Decoding encrypted data in \"{p[0]}\"...");

                byte[] encryptedData;
                byte[] encryptedFilename;
                EmbeddedDataType embeddedDataType = Decode(image, bitsEncoded, out encryptedData, out encryptedFilename);

                switch (embeddedDataType)
                {
                    case EmbeddedDataType.Message:
                        if (ShowDebugInfo) Console.WriteLine($"Decrypting message...");
                        byte[] message = Decrypt(encryptedData, password);
                        if (ShowDebugInfo) Console.Write("\nHidden message: ");
                        Console.WriteLine(BitEncoding.GetString(message));
                        break;
                    case EmbeddedDataType.File:
                        string filename = BitEncoding.GetString(Decrypt(encryptedFilename, password));
                        if (ShowDebugInfo) Console.WriteLine($"Found file: \"{filename}\"...");

                        if (!overrideFile(filename)) break;

                        byte[] data = Decrypt(encryptedData, password);
                        File.WriteAllBytes(filename, data);
                        //string content = BitEncoding.GetString(data);
                        //File.WriteAllText(filename, content);
                        Console.WriteLine($"Sucessfully extracted file \"{filename}\"!");
                        break;
                }
            }
            else
            {
                Console.WriteLine(Usage);
                return;
            }
        }

        static bool overrideFile(string filename)
        {
            if (File.Exists(filename))
            {
                Console.Write($"The file \"{filename}\" does already exist! Do you want to overwrite it? [y/n]: ");
                string q = Console.ReadLine();

                return q.ToLower() == "y";
            }
            return true;
        }

        private static byte[] Encrypt(byte[] data, string password)
        {
            if (password == null) return data;
            // Encryption using the Vigenère cipher
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) result[i] = (byte)( mod(data[i] + password[i % password.Length], byte.MaxValue) );
            return result;
        }
        private static byte[] Decrypt(byte[] data, string password)
        {
            if (password == null) return data;
            // Decryption using the Vigenère cipher
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) result[i] = (byte)( mod(data[i] - password[i % password.Length], byte.MaxValue));
            return result;
        }

        static int mod(int x, int m)
        {
            int r = x % m;
            return r < 0 ? r + m : r;
        }

        private static Bitmap getImage(string[] p)
        {
            if (!File.Exists(p[0])) { Console.WriteLine("The image was not found..."); return null; }
            return Image.FromFile(p[0]) as Bitmap;
        }

        private static EmbeddedDataType Decode(Bitmap image, int encodedBits, out byte[] data, out byte[] filename)
        {
            //byte[] mBuff = new byte[(int)Math.Ceiling(image.Width * (double)image.Height / encodedBits)];
            //int bIndex  = 0;
            EmbeddedDataType embeddedDataType = EmbeddedDataType.Unknown;
            byte[] embeddedFilename = null;
            List<byte> mBuff = new List<byte>();
            byte cBuff  = 0;
            int counter = 0;

            byte[] matchEndOfDataStream = new byte[EndOfDataStreamSequense.Length];

            bool isFirstByte = true;

            bool addPart(byte part)
            {
                cBuff = (byte)( (cBuff << encodedBits) + part);
                counter++;
                
                if (counter >= 8 / encodedBits)
                {
                    byte dByte = DecodeByte(cBuff, encodedBits);

                    addByte:
                    if (isFirstByte)
                    {
                        isFirstByte = false;
                        // try to convert byte to EmbeddedDataType
                        embeddedDataType = (EmbeddedDataType)dByte;
                        if (!Enum.IsDefined(typeof(EmbeddedDataType), embeddedDataType) && !embeddedDataType.ToString().Contains(","))
                        {
                            embeddedDataType = EmbeddedDataType.Message;
                            // The byte was unknown, therefore it must be part of the message
                            goto addByte;
                        }
                        else
                        {
                            // Reset all variables
                            cBuff = 0;
                            counter = 0;
                        }
                        if (ShowDebugInfo) Console.WriteLine($"Classifies embedded data as: {embeddedDataType.ToString()}...");
                    }
                    else
                    {
                        // Check for en of transmission
                        if (matchEndOfDataStream.SequenceEqual(EndOfDataStreamSequense)) // Was last byte of message
                        {
                            if (embeddedDataType == EmbeddedDataType.Message) return true;
                            else if (embeddedFilename == null)
                            {
                                embeddedFilename = mBuff.GetRange(0, mBuff.Count - EndOfDataStreamSequense.Length).ToArray();
                                mBuff = new List<byte>();
                                mBuff.Add(dByte);
                                cBuff = 0;
                                counter = 0;

                                ShiftAndAddByte(ref matchEndOfDataStream, dByte);
                                return false;
                            }
                            else
                            {
                                return true;
                            }
                        }
                        mBuff.Add(dByte);
                        cBuff = 0;
                        counter = 0;

                        ShiftAndAddByte(ref matchEndOfDataStream, dByte);
                    }
                }
                return false; // Was not last byte of message
            }

            EmbeddedDataType onReturn(out byte[] d, out byte[] f)
            {
                d = mBuff.GetRange(0, mBuff.Count - EndOfDataStreamSequense.Length).ToArray();
                f = embeddedFilename;
                return embeddedDataType;
            }

            for (int h = 0; h < image.Height; h++)
            {
                for (int w = 0; w < image.Width; w++)
                {
                    Color pixel = image.GetPixel(w, h);
                    byte r = (byte)(pixel.R ^ ((pixel.R >> encodedBits) << encodedBits));
                    byte g = (byte)(pixel.G ^ ((pixel.G >> encodedBits) << encodedBits));
                    byte b = (byte)(pixel.B ^ ((pixel.B >> encodedBits) << encodedBits));

                    if (addPart(r)) return onReturn(out data, out filename);
                    if (addPart(g)) return onReturn(out data, out filename);
                    if (addPart(b)) return onReturn(out data, out filename);
                }
            }

            //return message;
            return onReturn(out data, out filename);
        }

        private static void ShiftAndAddByte(ref byte[] arr, byte dByte)
        {
            for (int i = 0; i < arr.Length - 1; i++)
            {
                arr[i] = arr[i+1];
            }
            arr[arr.Length - 1] = dByte;
        }

        private static byte DecodeByte(byte cBuff, int bitsEncoded)
        {
            byte nByte = 0;
            for(int i = 0; i < 8 / bitsEncoded; i++)
            {
                byte bit = (byte)( ((cBuff >> bitsEncoded) << bitsEncoded) ^ cBuff );
                nByte += bit;

                cBuff >>= bitsEncoded;
                if (i < 8 / bitsEncoded - 1) nByte <<= bitsEncoded;
            }
            return nByte;
        }

        private static void EncodeMessage(Bitmap image, byte[] data, string output, int bitsToEncode)
        {
            List<byte> message = data.ToList();
            message.Insert(0, (byte)EmbeddedDataType.Message); // First byte represent the embedded data type
            message.AddRange(EndOfDataStreamSequense);

            int minImagePixels;
            if (!canBeEmbedded(message.Count, image, bitsToEncode, out minImagePixels))
            {
                int sideLen = (int)Math.Ceiling(Math.Sqrt(minImagePixels));
                Console.WriteLine("Error! Message could not be embedded, data is too large.");
                if (bitsToEncode != 8)
                {
                    Console.WriteLine("Try to increase the ammount of LSB to use, or");
                }
                Console.WriteLine($"Use a source image with a minimum area of {minImagePixels}px*px ({sideLen}px*{sideLen}px)");
                return;
            }

            List<byte> msgParts = new List<byte>(); // tuples of BitsEncoded-size

            byte selectByte = 0;
            for (int i = 0; i < bitsToEncode; i++) selectByte = (byte)( (selectByte << 0x1) | 0x1); // 000000 11
                                                                                                   //        ¨¨ Bits encoded selector
            for(int i = 0; i < message.Count; i++)
            {
                byte msgByte = message[i];
                for (int b = 0; b < 8 / bitsToEncode; b++)
                {
                    byte localSelect = (byte)(selectByte << (b * bitsToEncode));
                    byte bPart = (byte)( (msgByte & localSelect) >> (b * bitsToEncode));
                    msgParts.Add(bPart);
                }
            }

            int imgPixelIndex = 0;
            for (int i = 0; i < msgParts.Count; i += 0)
            {
                int x = imgPixelIndex % image.Width;
                int y = imgPixelIndex / image.Width;
                Color p = image.GetPixel(x, y);

                int r = p.R;
                int g = p.G;
                int b = p.B;

                if (i < msgParts.Count) r = ((p.R >> bitsToEncode) << bitsToEncode) + msgParts[i++];
                if (i < msgParts.Count) g = ((p.G >> bitsToEncode) << bitsToEncode) + msgParts[i++];
                if (i < msgParts.Count) b = ((p.B >> bitsToEncode) << bitsToEncode) + msgParts[i++];

                image.SetPixel(x, y, Color.FromArgb(p.A, r, g, b));

                if (i >= msgParts.Count) break;
                else imgPixelIndex++;
            }

            if (!overrideFile(output)) return;
            image.Save(output, System.Drawing.Imaging.ImageFormat.Bmp);
            image.Dispose();
        }

        private static void EncodeFile(Bitmap image, byte[] filename, byte[] data, string output, int bitsToEncode)
        {
            List<byte> dataToEncode = filename.ToList();
            dataToEncode.Insert(0, (byte)EmbeddedDataType.File); // First byte represent the embedded data type
            dataToEncode.AddRange(EndOfDataStreamSequense);
            dataToEncode.AddRange(data);
            dataToEncode.AddRange(EndOfDataStreamSequense);

            int minImagePixels;
            if (!canBeEmbedded(dataToEncode.Count, image, bitsToEncode, out minImagePixels))
            {
                int sideLen = (int)Math.Ceiling(Math.Sqrt(minImagePixels));
                Console.WriteLine("Error! File could not be embedded, data is too large.");
                if (bitsToEncode != 8)
                {
                    Console.WriteLine("Try to increase the ammount of LSB to use, or");
                }
                Console.WriteLine($"Use a source image with a minimum area of {minImagePixels}px*px ({sideLen}px*{sideLen}px)");
                return;
            }

            List<byte> msgParts = new List<byte>(); // tuples of BitsEncoded-size

            byte selectByte = 0;
            for (int i = 0; i < bitsToEncode; i++) selectByte = (byte)((selectByte << 0x1) | 0x1); // 000000 11
                                                                                                   //        ¨¨ Bits encoded selector
            for (int i = 0; i < dataToEncode.Count; i++)
            {
                byte msgByte = dataToEncode[i];
                for (int b = 0; b < 8 / bitsToEncode; b++)
                {
                    byte localSelect = (byte)(selectByte << (b * bitsToEncode));
                    byte bPart = (byte)((msgByte & localSelect) >> (b * bitsToEncode));
                    msgParts.Add(bPart);
                }
            }

            int imgPixelIndex = 0;
            for (int i = 0; i < msgParts.Count; i += 0)
            {
                int x = imgPixelIndex % image.Width;
                int y = imgPixelIndex / image.Width;
                Color p = image.GetPixel(x, y);

                int r = p.R;
                int g = p.G;
                int b = p.B;

                if (i < msgParts.Count) r = ((p.R >> bitsToEncode) << bitsToEncode) + msgParts[i++];
                if (i < msgParts.Count) g = ((p.G >> bitsToEncode) << bitsToEncode) + msgParts[i++];
                if (i < msgParts.Count) b = ((p.B >> bitsToEncode) << bitsToEncode) + msgParts[i++];

                image.SetPixel(x, y, Color.FromArgb(p.A, r, g, b));

                if (i >= msgParts.Count) break;
                else imgPixelIndex++;
            }

            if (!overrideFile(output)) return;
            image.Save(output, System.Drawing.Imaging.ImageFormat.Bmp);
            image.Dispose();
        }

        private static bool canBeEmbedded(int count, Bitmap image, int lsb, out int minPixels)
        {
            minPixels = count / lsb;
            int pixels = image.Width * image.Height;
            return pixels > minPixels;
        }
    }
}
