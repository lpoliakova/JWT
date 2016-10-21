using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using JSONWebToken.Models;

namespace JSONWebToken.Controllers
{
    [RoutePrefix("api/account")]
    public class AccountsController : ApiController
    {
        [Route("")]
        public IHttpActionResult Get()
        {
            string encodedJWT = Request.Headers.GetValues("JWT").First();

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken decodedJWT;
            try
            {
                decodedJWT = tokenHandler.ReadJwtToken(encodedJWT);
            }
            catch (Exception)
            {
                return BadRequest("token was not correct");
            }

            return Ok(decodedJWT);
        }

        [HttpGet, Route("token")]
        public IHttpActionResult GetToken()
        {
            string name = Request.Headers.GetValues("UserName").First();
            string token = (new GeneratingJWT()).GenerateJWT(new User { UserName = name, App = "app", Device = "device" });
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
