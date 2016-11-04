using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Web;

namespace JSONWebToken.Tokens
{
    public class Token
    {
        protected static JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

        #region Properties
        
        public string UserId { get; private set; }
        public string AdminId { get; private set; }
        public string AppId { get; private set; }
        public string Platform { get; private set; }
        public string DeviceId { get; private set; }
        public DateTime IssueTime { get; private set; }
        //public bool IsAdmin { get { return AdminId != null && UserId == null; } }

        #endregion

        #region 'ctors

        protected Token() { }

        public Token(string userId, string appId, string platform, string deviceId)
        {
            UserId = userId;
            AppId = appId;
            DeviceId = deviceId;
            Platform = platform;
            IssueTime = DateTime.Now;
            AdminId = null;
        }

        public Token(string adminId, string appId)
        {
            UserId = null;
            AppId = appId;
            DeviceId = "default";
            Platform = "none";
            IssueTime = DateTime.Now;
            AdminId = adminId;
        }

        #endregion

        private IEnumerable<Claim> GetParameters()
        {
            return new List<Claim>
            {
                new Claim("UserId",  UserId ?? ""),
                new Claim("AdminId",  AdminId ?? ""),
                new Claim("AppId",  AppId ?? ""),
                new Claim("Platform",  Platform ?? ""),
                new Claim("DeviceId",  DeviceId ?? ""),
            };
        }

        private Token SetParameters(IEnumerable<Claim> claims)
        {
            UserId = claims.Where(claim => claim.Type == "UserId").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First();
            AdminId = claims.Where(claim => claim.Type == "AdminId").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First();
            AppId = claims.Where(claim => claim.Type == "AppId").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First();
            Platform = claims.Where(claim => claim.Type == "Platform").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First();
            DeviceId = claims.Where(claim => claim.Type == "DeviceId").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First();
            IssueTime = DateTime.Parse(claims.Where(claim => claim.Type == "IssueTime").Select(claim => string.IsNullOrEmpty(claim.Value) ? null : claim.Value).First());
            return this;
        }

        protected virtual SigningCredentials GetSigningCredentials() // where we take key and algorithm? 
        {
            return null;
        }

        private string SerializeToken() // nearly not used
        {
            var claims = GetParameters();
            var signingCredentials = GetSigningCredentials();
            JwtSecurityToken jwt = new JwtSecurityToken(
                claims: claims,
                notBefore: IssueTime,
                expires: IssueTime.AddSeconds(30), // where we take expiration time?
                signingCredentials: signingCredentials);
            return _tokenHandler.WriteToken(jwt);
        }

        private static Token DeserializeToken(string token) // not used
        {
            JwtSecurityToken jwtToken = _tokenHandler.ReadJwtToken(token);
            return (new Token()).SetParameters(jwtToken.Claims);
        }

        protected virtual TokenValidationParameters GetValidationParameters()
        {
            return new TokenValidationParameters
            {
                RequireExpirationTime = true,
                ValidateLifetime = true,

                RequireSignedTokens = false,
                ValidateIssuerSigningKey = false,

                ValidateActor = false,
                ValidateAudience = false,
                ValidateIssuer = false,
            };
        }

        public void ParseAndValidate(string token)
        {
            try
            {
                SecurityToken jwt;
                TokenValidationParameters validationParams = GetValidationParameters();
                _tokenHandler.ValidateToken(token, validationParams, out jwt);
                this.SetParameters(((JwtSecurityToken)jwt).Claims);
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException(ex.Message); // not shure that it is possible to give different exceptions
            }
        }

        public void Validate() // not used
        {
            throw new NotImplementedException();
        }

        public override string ToString()
        {
            return SerializeToken();
        }

        public string RenewToken(string token)
        {
            ParseAndValidate(token);

            IssueTime = DateTime.Now;
            return ToString();
        }

        public JwtSecurityToken GetJWT(string token)
        {
            try
            {
                SecurityToken jwt;
                TokenValidationParameters validationParams = GetValidationParameters();
                _tokenHandler.ValidateToken(token, validationParams, out jwt);
                return (JwtSecurityToken)jwt;
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException(ex.Message);
            }
        }
    }
}