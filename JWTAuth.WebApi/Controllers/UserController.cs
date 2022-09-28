using JWTAuth.WebApi.Models;
using JWTAuth.WebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.WebApi.Controllers
{
    [Authorize]
    [Route("api/[Controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly UserService service;

        public UserController(UserService _service)
        {
            service = _service;
        }
       
        [HttpGet]
        public ActionResult<List<User>> GetUsers()
        {
            return service.GetUsers();
        }
      
        [HttpGet("{id:length(24)}")]
        public ActionResult<User> GetUser(string id)
        {
            var user = service.GetUser(id);
            return Json(user);
        }
      
        [AllowAnonymous]
        [HttpPost("Create")]
        public ActionResult<User> Create(User ur)
        {
            service.Create(ur);
            return Json(ur);
        }
      
        [AllowAnonymous]
        [Route("Authenticate")]
        [HttpPost]
        public ActionResult Login([FromBody] User user)
        {
            var token = service.Authenticate(user.email, user.password);
            return Ok(new { token, user });
        }
        //public IActionResult Refresh(Tokens token)
        //{
        //    var principle = service.GetPrincipalFromExpiredToken(token.Access_Token);

        //}
      
        [AllowAnonymous]
        [Route("Refresh")]
        [HttpPost]
        public ActionResult Refresh( Tokens token)
        {
            var tokens = service.Refresh(token);
            return Ok(new { tokens });
        }
    }
}
