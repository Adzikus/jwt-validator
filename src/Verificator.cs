using System;
using System.IO;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace JwtVerificator
{
    public class Verificator : IVerificator
    {
        private readonly JwtVerificatorSettings _settings;

        public Verificator(JwtVerificatorSettings settings)
        {
            _settings = settings;
        }

        public bool SimpleECDsaValidation(string token)
        {
            try
            {
                var securityToken = new JwtSecurityToken(token);
                var securityTokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = securityToken.Issuer,
                    ValidateAudience = false,
                    IssuerSigningKey = new ECDsaSecurityKey(ReadPublicKey())
                };
                var claims = securityTokenHandler.ValidateToken(token, validationParameters, out _);
                return true;
            }
            catch (System.Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool SimpleRSAValidation(string token)
        {
            throw new NotImplementedException();
        }

        private ECDsa ReadPublicKey()
        {
            var ecdsa = new ECDsaCng()
            {
                HashAlgorithm = CngAlgorithm.ECDsaP256
            };
            ecdsa.ImportSubjectPublicKeyInfo(File.ReadAllBytes(_settings.ECDsaPublicKeyPath), out int x);
            return ecdsa;
        }
    }
}