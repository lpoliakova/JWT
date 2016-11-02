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
        public static readonly HMACSHA256 hmac = new HMACSHA256();

        public static string GetAlgorithm()
        {
            return "HS256";
        }

    }
}