using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace JobviteApiConnectorCSharp
{
    public class JvResponse
    {
        public String key { get; set; }
        public String payload { get; set; }
    }
    class Program
    {
        static String customerPrivateKeyPath = @"customer's der format private key path";
        static String jobvitePublicKeyPath = @"jobvite's der format public key path";
        static String apiKey = "apikey";
        static String apiSecret = "344b47c692dba4a3ba4e8200eb8fd5c9";
        static String baseUrl = @"https://api.jobvite.com/api/v2/task?api={0}&sc={1}";

        /**
         * User can use either pem format file or der format file. Below param is required only if user wants to use der format file
         * Also to use pem format file call PublicKeyFromPemFile method in  EncryptStringToBytes rather than PublicKeyFromDerFile . Also use 
         * GetPrivateKeyFromPemFile method in Decrypt method rather than using GetPrivateKeyFromDerFile
         */

        static String customerPemPrivateKeyPath = "customer's pem format private key path";
        static String jobvitePemPublicKeyPath = "jobvite's pem format public key path";

        static void Main(string[] args)
        {
            string jsonString = "{ \"filter\":{ \"task\":{ \"processInstanceId\":{ \"eq\":\"5fda297111edfb36b766c7871\" } } } }";
            String response = EncryptStringToBytes(jsonString);

            JvResponse jvResponse = JsonSerializer.Deserialize<JvResponse>(response);
            Console.WriteLine(jvResponse.key);
            Console.WriteLine(jvResponse.payload);

            Console.WriteLine(Decrypt(jvResponse));

        }


        private static string Decrypt(JvResponse jvResponse)
        {
            RSACryptoServiceProvider rSA = GetPrivateKeyFromDerFile();
            byte[] keyArr = rSA.Decrypt(Convert.FromBase64String(jvResponse.key), RSAEncryptionPadding.Pkcs1);

            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.BlockSize = 128;
            aesEncryption.KeySize = 256;

            aesEncryption.Mode = CipherMode.ECB;
            aesEncryption.Padding = PaddingMode.None;


            byte[] KeyArr32BytesValue = new byte[32];
            Array.Copy(keyArr, KeyArr32BytesValue, 32);

            aesEncryption.Key = KeyArr32BytesValue;

            ICryptoTransform decrypto = aesEncryption.CreateDecryptor();

            byte[] encryptedBytes = Convert.FromBase64CharArray(jvResponse.payload.ToCharArray(), 0, jvResponse.payload.Length);
            byte[] decryptedData = decrypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            return System.Text.ASCIIEncoding.UTF8.GetString(decryptedData);
        }

        static String EncryptStringToBytes(string plainText)
        {
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.GenerateKey();
                rijAlg.KeySize = 256;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.Mode = CipherMode.ECB;


                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))

                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {

                    swEncrypt.Write(plainText);
                    if (plainText.Length < 16)
                    {
                        for (int i = plainText.Length; i < 16; i++)
                            swEncrypt.Write((byte)0x0);
                    }
                    swEncrypt.Flush();
                    csEncrypt.FlushFinalBlock();
                    encrypted = msEncrypt.ToArray();
                }
                String payload = Convert.ToBase64String(encrypted);
                RSACryptoServiceProvider rSA = PublicKeyFromDerFile();
                byte[] key = rSA.Encrypt(rijAlg.Key, RSAEncryptionPadding.Pkcs1);


                return makePostRequest(Convert.ToBase64String(key), payload);
            }
        }

        public static String makePostRequest(String key, String payload)
        {
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(String.Format(baseUrl, apiKey, apiSecret));
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                var json = "{\"key\": \"" + key + "\", \"payload\":\"" + payload + "\"}";
                streamWriter.Write(json);
            }

            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                return streamReader.ReadToEnd();
            }
        }

        public static RSACryptoServiceProvider PublicKeyFromPemFile()
        {
            using (TextReader publicKeyTextReader = new StringReader(File.ReadAllText(jobvitePemPublicKeyPath)))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }



        public static RSACryptoServiceProvider PublicKeyFromDerFile()
        {
            String publicKeyDerBase64 = Convert.ToBase64String(File.ReadAllBytes(jobvitePublicKeyPath));
            byte[] publicKeyDerRestored = Convert.FromBase64String(publicKeyDerBase64);
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyDerRestored);

            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            RSAParameters parms = new RSAParameters();

            parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            cryptoServiceProvider.ImportParameters(parms);

            return cryptoServiceProvider;
        }

        public static RSACryptoServiceProvider GetPrivateKeyFromPemFile()
        {
            using (TextReader privateKeyTextReader = new StringReader(File.ReadAllText(customerPemPrivateKeyPath)))
            {
                RsaPrivateCrtKeyParameters readKeyPair = (RsaPrivateCrtKeyParameters)new PemReader(privateKeyTextReader).ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(readKeyPair);
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }

        public static RSACryptoServiceProvider GetPrivateKeyFromDerFile()
        {
            String publicKeyDerBase64 = Convert.ToBase64String(File.ReadAllBytes(customerPrivateKeyPath));
            byte[] publicKeyDerRestored = Convert.FromBase64String(publicKeyDerBase64);
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(publicKeyDerRestored);

            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(privateKeyParam);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
    }
}
