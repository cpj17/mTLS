using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        [Authorize(AuthenticationSchemes = "Certificate")]
        [Route("api/auth/login")]
        [HttpPost]
        public IActionResult Login([FromBody] clsRequest request)
        {
            if (request.UserName == "admin" && request.Password == "123")
            {
                return Ok(new
                {
                    Message = "Login success - mTLS authentication successful"
                });
            }

            return Ok(new
            {
                Message = "Login failed."
            });
        }
    }

    public class clsRequest
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
