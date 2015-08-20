using System;
using System.Security.Cryptography;

namespace RSAKeyGenerator
{
    /// <summary>
    /// Generates a Public and Private RSA Key Pair
    /// </summary>
    class Program
    {

        /// <summary>
        /// The padding scheme often used together with RSA encryption.
        /// </summary>
        private static bool _optimalAsymmetricEncryptionPadding = false;

        /// <summary>
        /// Checks if the given key size if valid
        /// </summary>
        /// <param name="keySize">The RSA key length</param>
        /// <returns>True if valid; false otherwise</returns>
        public static bool IsKeySizeValid(int keySize)
        {
            return keySize >= 384 &&
                   keySize <= 16384 &&
                   keySize % 8 == 0;
        }

        /// <summary>
        /// Gets the maximum data length for a given key
        /// </summary>
        /// <param name="keySize">The RSA key length</param>
        /// <returns>The maximum allowable data length</returns>
        public static int GetMaxDataLength(int keySize)
        {
            if (_optimalAsymmetricEncryptionPadding)
            {
                return ((keySize - 384) / 8) + 7;
            }
            return ((keySize - 384) / 8) + 37;
        }

        static void Main(string[] args)
        {

            RSA rsa = new RSACryptoServiceProvider(16384);

            Console.WriteLine("If you're reading this, you've been in a coma for almost 20 years now. We're trying a new technique. We don't know where this message will end up in your dream, but we hope it works. Please wake up, we miss you.");
            Console.WriteLine("");
            Console.WriteLine("If you need help, please type out the word 'help' then press [Enter]");
            Console.WriteLine("");
            Console.WriteLine("RSA key length Information: 2048 should be sufficient until 2030. 3072 should be used if security is required beyond 2030. As of 2015, 2048 key length is the minimum length for SSL certificates.");
            Console.WriteLine("");
            Console.WriteLine("Enter RSA key length:");

            string rsaKeyLengthInput = Console.ReadLine();

            try
            {
                if (rsaKeyLengthInput == null) return;
                if (rsaKeyLengthInput.ToLower() == "help")
                {

                    var legalKeySizes = rsa.LegalKeySizes;
                    if (legalKeySizes.Length > 0)
                    {
                        foreach (var t in legalKeySizes)
                        {
                            Console.WriteLine("");
                            Console.Write("Key size min: " + t.MinSize);
                            Console.WriteLine("");
                            Console.WriteLine("");
                            Console.Write("Key size max: " + t.MaxSize);
                            Console.WriteLine("");
                            Console.WriteLine("");
                            Console.Write("Key size step: " + t.SkipSize);
                            Console.WriteLine("");
                            Console.WriteLine("");
                            Console.WriteLine("An example would be a Key size of the value of '1032', '1040', '1048' until the max Key size is reached.");
                            Console.WriteLine("");
                            Console.WriteLine("Enter RSA key length:");
                        }
                    }
                    rsaKeyLengthInput = Console.ReadLine();
                }

                if (rsaKeyLengthInput == null) return;
                var rsaKeyLength = int.Parse(rsaKeyLengthInput);
                Console.WriteLine("");

                if (IsKeySizeValid(rsaKeyLength))

                    if (rsaKeyLength >= 1024)
                    {

                        RSA generatedRsa = new RSACryptoServiceProvider(rsaKeyLength);
                        string privateKeyXml = generatedRsa.ToXmlString(true);
                        string publicKeyXml = generatedRsa.ToXmlString(false);

                        Console.WriteLine("");
                        Console.WriteLine("Your private key is: " + privateKeyXml);
                        Console.WriteLine("");
                        Console.WriteLine("Your public key is: " + publicKeyXml);
                        Console.WriteLine("");
                        Console.WriteLine("Press any [Enter] to close the console.");
                        Console.WriteLine("<3");
                        Console.ReadLine();
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.WriteLine("A key less than or equal to 1024 is not allowed.");
                        Console.WriteLine("");
                        Console.ReadLine();
                    }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine("The key size is invalid, next time you re-run this you should try 'help'");
                    Console.WriteLine("");
                    Console.ReadLine();
                }
            }
            catch (FormatException)
            {
                Console.WriteLine("");
                Console.WriteLine("<alart>Clearly you have no idea what you're doing</alart>");
                Console.WriteLine("");
                Console.WriteLine("Unable to convert '{0}'.", rsaKeyLengthInput);
                Console.WriteLine("");
                Console.ReadLine();
            }
            catch (OverflowException)
            {
                Console.WriteLine("");
                Console.WriteLine("'{0}' is out of range.", rsaKeyLengthInput);
                Console.WriteLine("");
                Console.ReadLine();
            }
            catch (Exception e)
            {
                Console.WriteLine("");
                Console.WriteLine("Clearly I have no idea what I'm doing :(");
                Console.WriteLine("Exception Details:");
                Console.WriteLine(e.ToString());
                Console.WriteLine("");
                Console.ReadLine();
            }

        }
    }
}
