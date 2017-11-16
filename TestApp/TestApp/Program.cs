using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace TestApp
{
    class Program
    {
        // x509

        static SecurityTokenDescriptor x509_2048_descriptor = new SecurityTokenDescriptor()
        {
            Issuer = "issuer",
            Audience = "audience",
            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2
        };

        static TokenValidationParameters x509_2048_tvp = new TokenValidationParameters()
        {
            IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
            ValidIssuer = "issuer",
            ValidAudience = "audience"
        };

        // jwk rsa

        static SecurityTokenDescriptor jwk_rsa_descriptor = new SecurityTokenDescriptor()
        {
            Issuer = "issuer",
            Audience = "audience",
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };

        static TokenValidationParameters jwk_rsa_tvp = new TokenValidationParameters()
        {
            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256,
            ValidIssuer = "issuer",
            ValidAudience = "audience"
        };

        // rsa 2048

        static SecurityTokenDescriptor rsa_2048_descriptor = new SecurityTokenDescriptor()
        {
            Issuer = "issuer",
            Audience = "audience",
            SigningCredentials = KeyingMaterial.RSASigningCreds_2048
        };

        static TokenValidationParameters rsa_2048_tvp = new TokenValidationParameters()
        {
            IssuerSigningKey = KeyingMaterial.RsaSecurityKey_2048,
            ValidIssuer = "issuer",
            ValidAudience = "audience"
        };

        // sym 256

        static SecurityTokenDescriptor sym_256_descriptor = new SecurityTokenDescriptor()
        {
            Issuer = "issuer",
            Audience = "audience",
            SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2
        };

        static TokenValidationParameters sym_256_tvp = new TokenValidationParameters()
        {
            IssuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256,
            ValidIssuer = "issuer",
            ValidAudience = "audience"
        };

        static JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();


        static double CreateAndValidateToken(int numberOfIterations, SecurityTokenDescriptor descriptor, TokenValidationParameters tvp)
        {
            Stopwatch sw = Stopwatch.StartNew();
            for(int i = 0; i < numberOfIterations; i++)
            {
                var token = handler.CreateEncodedJwt(descriptor);
                handler.ValidateToken(token, tvp, out SecurityToken validatedToken);
            }
            sw.Stop();
            var totalTime = sw.Elapsed.TotalMilliseconds;
            //Console.WriteLine($"total time: {totalTime}");
            return totalTime;
        }

        static void RunTest(SecurityTokenDescriptor descriptor, TokenValidationParameters tvp)
        {
            double total = 0;
            for (int i = 0; i < 10; i++)
            {
                total += CreateAndValidateToken(30, descriptor, tvp);
            }
            Console.WriteLine($"Total time is {total}");
        }

        static void Main(string[] args)
        {           
            Console.WriteLine("x509 test");
            RunTest(x509_2048_descriptor, x509_2048_tvp);
            Console.WriteLine("jwk rsa");
            RunTest(jwk_rsa_descriptor, jwk_rsa_tvp);
            Console.WriteLine("rsa 2048");
            RunTest(rsa_2048_descriptor, rsa_2048_tvp);
            Console.WriteLine("sym 256");
            RunTest(sym_256_descriptor, sym_256_tvp);
            Console.WriteLine($"===================================");
            Console.WriteLine("Press any key.");
            Console.ReadKey();
        }
    }
}
