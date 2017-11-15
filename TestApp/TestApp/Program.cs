﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace TestApp
{
    class Program
    {
        static void Prepare()
        {
            // 2048 bit RSA

            var CertPassword = "abc";
            var DefaultX509Data_2048 = @"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";
            var DefaultCert_2048 = new X509Certificate2(Convert.FromBase64String(DefaultX509Data_2048), CertPassword, X509KeyStorageFlags.MachineKeySet);
            var DefaultX509Key_2048_KeyId = "DefaultX509Key_2048_KeyId";
            //var DefaultX509Key_2048_Thumbprint = "pqoeamb2e5YVzR6_rqFpiCrFZgw";
            var DefaultX509Key_2048 = new X509SecurityKey(DefaultCert_2048);
            var DefaultX509Key_2048_With_KeyId = new X509SecurityKey(DefaultCert_2048) { KeyId = DefaultX509Key_2048_KeyId };
            var DefaultX509SigningCreds_2048_RsaSha2_Sha2 = new SigningCredentials(DefaultX509Key_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            var DefaultAsymmetricCert_2048 = new X509Certificate2(Convert.FromBase64String(DefaultX509Data_2048), CertPassword, X509KeyStorageFlags.MachineKeySet);


            // symmetric key
            var DefaultSymmetricKeyEncoded_256 = "Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=";
            var DefaultSymmetricKeyBytes_256 = Convert.FromBase64String(DefaultSymmetricKeyEncoded_256);
            var DefaultSymmetricSecurityKey_256 = new SymmetricSecurityKey(DefaultSymmetricKeyBytes_256) { KeyId = "DefaultSymmetricSecurityKey_256" };
            var DefaultSymmetricSigningCreds_256_Sha2 = new SigningCredentials(DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256);
            var DefaultSymmetricEncryptingCreds_Aes128_Sha2 = new EncryptingCredentials(DefaultSymmetricSecurityKey_256, "dir", SecurityAlgorithms.Aes128CbcHmacSha256);

    }
    static double RunTests(int numberOfIterations)
        {
            Stopwatch sw = Stopwatch.StartNew();

            sw.Stop();
            var totalTime = sw.Elapsed.TotalMilliseconds;
            return sw.Elapsed.TotalMilliseconds;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }
}
}
