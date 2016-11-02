using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using JSONWebToken.Models;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using JSONWebToken.Signature;
using System.Text;

namespace JSONWebToken
{
    public class GeneratingJWT
    {
        // User user = new User { UserName = "user", App = "app", Device = "device" };

        private string GenerateJSON(User user)
        {
            string json = JsonConvert.SerializeObject(user);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(json);
            string payloadBase64 =  System.Convert.ToBase64String(payloadBytes);
            //Generate a public/private key pair.
            //RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //Save the public key information to an RSAParameters structure.
            //RSAParameters RSAKeyInfo = RSA.ExportParameters(false);

            var signitureBytes = KeyGeneration.hmac.ComputeHash(payloadBytes);
            string signatureBase64 = System.Convert.ToBase64String(signitureBytes);
            return "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + payloadBase64 + "." + signatureBase64;
        }

        private string GenerateToken(User user)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = new JwtSecurityToken();
            
            return jwt.ToString();
        }

        public string GenerateJWT(User user)
        {
            //return GenerateToken(user);
            return GenerateJSON(user);
        }
    }
}