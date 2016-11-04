using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace JSONWebToken.Signature
{
    public static class KeyGeneration
    {
        private static readonly HMACSHA256 hmac = new HMACSHA256();

        public static string GetAlgorithm()
        {
            return "HS256";
        }

        public static byte[] GetKey()
        {
            return hmac.Key;
        }
        
    }
}