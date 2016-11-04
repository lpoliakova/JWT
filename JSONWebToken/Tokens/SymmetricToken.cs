using JSONWebToken.Models;
using JSONWebToken.Signature;

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Web;

namespace JSONWebToken.Tokens
{
    public class SymmetricToken : Token
    {
        #region 'ctors

        public SymmetricToken() : base() { }

        public SymmetricToken(string userId, string appId, string platform, string deviceId) : base(userId, appId, platform, deviceId) { }

        public SymmetricToken(string adminId, string appId) : base(adminId, appId) { }

        #endregion

        protected override SigningCredentials GetSigningCredentials()
        {
            return new SigningCredentials( 
                new SymmetricSecurityKey(KeyGeneration.GetKey()),
                KeyGeneration.GetAlgorithm());
        }

        protected override TokenValidationParameters GetValidationParameters()
        {
            var signingKey = GetSigningCredentials()?.Key;
            return new TokenValidationParameters
            {
                RequireExpirationTime = true,
                ValidateLifetime = true,

                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                //CryptoProviderFactory = new CryptoProviderFactory(),

                ValidateActor = false,
                ValidateAudience = false,
                ValidateIssuer = false,
            };
        }
    }
}