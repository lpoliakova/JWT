using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using JSONWebToken.Models;
using JSONWebToken.Signature;
using System.Text;

namespace JSONWebToken.Controllers
{
    [RoutePrefix("api/account")]
    public class AccountsController : ApiController
    {

        private JwtSecurityToken ValidateToken(JwtSecurityTokenHandler tokenHandler, string jwt)
        {
            SecurityToken token;
            var signingCredentials = new SymmetricSecurityKey(KeyGeneration.hmac.Key);
            TokenValidationParameters validationParams = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                ValidateLifetime = true,

                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingCredentials,
                CryptoProviderFactory = new CryptoProviderFactory(),

                ValidateActor = false,
                ValidateAudience = false,
                ValidateIssuer = false,
            };
            tokenHandler.ValidateToken(jwt, validationParams, out token);
            return (JwtSecurityToken)token;
        }

        [Route("")]
        public IHttpActionResult Get()
        {
            string encodedJWT = Request.Headers.GetValues("JWT").First();

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            //ValidateToken(tokenHandler, encodedJWT);
            JwtSecurityToken decodedJWT;
            try
            {
                decodedJWT = ValidateToken(tokenHandler, encodedJWT);
                //decodedJWT = tokenHandler.ReadJwtToken(encodedJWT);
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }

            return Ok(decodedJWT);
        }

        [HttpGet, Route("token")]
        public IHttpActionResult GetToken()
        {
            string name = Request.Headers.GetValues("UserName").First();
            //string token = (new GeneratingJWT()).GenerateJSON(new User { UserName = name, App = "app", Device = "device" });
            string token = (new GeneratingJWT()).GenerateJWTWithSignature(new User { UserName = name, App = "app", Device = "device" });
            return Ok(token);
        }

        [Authorize]
        [Route("user")]
        public IHttpActionResult GetUser()
        {
            return Ok(new User { UserName = "name", App = "app", Device = "device" });
        }

        [Route("create")]
        public IHttpActionResult CreateUser([FromBody] User createUserModel)
        {
            return Ok("created " + createUserModel.UserName);
        }

    }
}
