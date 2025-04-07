using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Services.Interfaces;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userServices;
        private readonly SignInManager<User> _signInManager;
        private readonly IExternalAuthService _externalAuthService;

        public AuthController(IUserService userServices, SignInManager<User> signInManager,   IExternalAuthService externalAuthService)
        {
            _userServices = userServices;
            _signInManager = signInManager;
            _externalAuthService = externalAuthService;
        }
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            
            var reponse = await _userServices.RegisterAsync(request);
            return Ok(reponse);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
           {
            var reponse = await _userServices.LoginAsync(request);
            return Ok(reponse);
        }

        //get user by id
        [HttpGet("{id}")]
        [Authorize(Roles = "USER,ADMIN")]
        public async Task<IActionResult> GetById(Guid id)
        {
            var reponse = await _userServices.GetByIdAsync(id);
            return Ok(reponse);
        }

        //refresh token
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var reponse = await _userServices.RefreshTokenAsync(request);
            return Ok(reponse);
        }

        //revoke refresh token
        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest request)
        {
            var response = await _userServices.RevokeRefreshToken(request);
            if (response.IsSuccess)
            {
                return Ok(response);
            }

             return BadRequest(response);
        }

        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var response = await _userServices.GetCurrentUserAsync();
            return Ok(response);
        }
        // 1) API gọi để lấy link Google OAuth2
        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", Url.Action("GoogleResponse", "Auth"));
            return new ChallengeResult("Google", properties);
        }

        // 2) Google callback trả về đây
        [HttpGet("google-response")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await _externalAuthService.ProcessGoogleLoginAsync();
            if (!result.IsSuccess)
                return BadRequest();
            return Ok(result.Data);
        }
    }
}
