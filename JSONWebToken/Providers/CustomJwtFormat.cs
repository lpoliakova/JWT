using JSONWebToken.Models;
using JSONWebToken.Signature;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Web;

namespace JSONWebToken.Providers
{
    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {

        private readonly string _issuer = string.Empty;

        public CustomJwtFormat(string issuer)
        {
            _issuer = issuer;
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            User user = new User { UserName = data.Identity.Name, App = "app", Device = "device"};
            string json = JsonConvert.SerializeObject(user);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(json);
            string payloadBase64 = System.Convert.ToBase64String(payloadBytes);

            var signitureBytes = KeyGeneration.hmac.ComputeHash(payloadBytes);
            string signatureBase64 = System.Convert.ToBase64String(signitureBytes);
            return "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + payloadBase64 + "." + signatureBase64;

            //string audienceId = "audienceId";

            //var signingKey = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(KeyGeneration.GetBase64Key()));

            //var issued = data.Properties.IssuedUtc;

            //var expires = data.Properties.ExpiresUtc;

            //var token = new JwtSecurityToken(_issuer, audienceId, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingKey);

            //var handler = new JwtSecurityTokenHandler();

            //var jwt = handler.WriteToken(token);

            //return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}