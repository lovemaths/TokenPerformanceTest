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

        static void Prepare()
        {
            var token = handler.CreateEncodedJwt(sym_256_descriptor);

            handler.ValidateToken(token, sym_256_tvp, out SecurityToken validatedToken);
        }

        static double RunTests(int numberOfIterations)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Prepare();
            sw.Stop();
            var totalTime = sw.Elapsed.TotalMilliseconds;
            return sw.Elapsed.TotalMilliseconds;
        }

        static void Main(string[] args)
        {
            RunTests(10);
            Console.WriteLine("Hello World!");
        }
    }
}
