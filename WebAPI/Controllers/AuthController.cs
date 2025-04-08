using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly SignInManager<User> _signInManager;
        private readonly IExternalAuthService _externalAuthService;

        public AuthController(IUserService userServices, SignInManager<User> signInManager,   IExternalAuthService externalAuthService)
        {
            _userService = userServices;
            _signInManager = signInManager;
            _externalAuthService = externalAuthService;
        }
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            
            var reponse = await _userService.RegisterAsync(request);
            return Ok(reponse);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
           {
            var reponse = await _userService.LoginAsync(request);
            return Ok(reponse);
        }

        [HttpPatch]
        public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request)
        {
            var response = await _userService.UpdateCurrentUserAsync(request);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }
            return Ok(response);
        }
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var response = await _userService.ChangePasswordAsync(request);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }
            return Ok(response);
        }

        //refresh token
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var reponse = await _userService.RefreshTokenAsync(request);
            return Ok(reponse);
        }

        //revoke refresh token
        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest request)
        {
            var response = await _userService.RevokeRefreshTokenAsync(request);
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
            var response = await _userService.GetCurrentUserAsync();
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
