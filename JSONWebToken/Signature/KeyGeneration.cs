using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using Thinktecture.IdentityModel.Tokens;

namespace JSONWebToken.Signature
{
    public static class KeyGeneration
    {
        public static readonly HMACSHA256 hmac = new HMACSHA256();
        
        public static string GetBase64Key()
        {
            return Convert.ToBase64String(hmac.Key);
        }

        public static HmacSigningCredentials GetSigningCredentials()
        {
            return new HmacSigningCredentials(hmac.Key);
        }

        public static string GetAlgorithm()
        {
            return "HMACSHA256";
        }

    }
}