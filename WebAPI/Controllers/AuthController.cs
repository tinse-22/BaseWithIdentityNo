using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IExternalAuthService _externalAuthService;
        private readonly SignInManager<User> _signInManager;

        public AuthController(IUserService userService, IExternalAuthService externalAuthService,  SignInManager<User> signInManager)
        {
            _userService = userService;
            _externalAuthService = externalAuthService;
            _signInManager = signInManager;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            var result = await _userService.RegisterAsync(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

        [HttpGet("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(Guid userId, string token)
        {
            if (userId == Guid.Empty || string.IsNullOrWhiteSpace(token))
                return BadRequest("Invalid parameters");

            var result = await _userService.ConfirmEmailAsync(userId, token);

            if (result.IsSuccess)
                return Ok(new { success = true, message = result.Message });
            else
                return BadRequest(new { success = false, message = result.Message });
        }

        [HttpPost("resend-confirmation")]
        [AllowAnonymous]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendEmailRequestDTO dto)
        {
            var result = await _userService.ResendConfirmationEmailAsync(dto.Email);
            return Ok(result.Message);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            var result = await _userService.LoginAsync(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDTO req)
        {
            if (!ModelState.IsValid)
                return BadRequest("Dữ liệu không hợp lệ.");
            var result = await _userService.InitiatePasswordResetAsync(req);
            return Ok(result.Message);
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDTO req)
        {
            if (!ModelState.IsValid)
                return BadRequest("Dữ liệu không hợp lệ.");
            var result = await _userService.ResetPasswordAsync(req);
            return result.IsSuccess ? Ok(result.Message) : BadRequest(result.Message);
        }

        [HttpPost("send-2fa-code")]
        [Authorize]
        public async Task<IActionResult> Send2FACode()
        {
            var result = await _userService.Send2FACodeAsync();
            return result.IsSuccess ? Ok(result.Message) : BadRequest(result.Message);
        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var result = await _userService.ChangePasswordAsync(request);
            return result.IsSuccess ? Ok(result.Message) : BadRequest(result.Message);
        }

        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _userService.RefreshTokenAsync(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _userService.RevokeRefreshTokenAsync(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var result = await _userService.GetCurrentUserAsync();
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action(nameof(GoogleResponse), "Auth");
            var props = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return Challenge(props, "Google");
        }

        [HttpGet("google-response")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await _externalAuthService.ProcessGoogleLoginAsync();
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
        [HttpPost("google-login-token")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleLoginToken([FromBody] GoogleLoginRequest request)
        {
            if (string.IsNullOrEmpty(request.TokenId))
                return BadRequest("Token ID is required");

            var result = await _externalAuthService.ProcessGoogleTokenAsync(request.TokenId);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
    }
}