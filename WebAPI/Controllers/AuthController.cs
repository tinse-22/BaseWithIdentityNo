using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Services.Commons.Gmail;   // IEmailService
namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly SignInManager<User> _signInManager;
        private readonly IExternalAuthService _externalAuthService;
        private readonly IEmailService _emailService;
        private readonly UserManager<User> _userManager;

        public AuthController(IUserService userServices, SignInManager<User> signInManager,  IExternalAuthService externalAuthService, IEmailService emailService, UserManager<User> userManager)
        {
            _userService = userServices;
            _signInManager = signInManager;
            _externalAuthService = externalAuthService;
            _emailService = emailService;
            _userManager = userManager;
        }

        // 1) Đăng ký & Gửi Welcome + Email Confirmation
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            var result = await _userService.RegisterAsync(request);
            if (!result.IsSuccess)
                return BadRequest(result);

            // Gửi email chào mừng
            await _emailService.SendWelcomeEmailAsync(request.Email);

            // Tạo token email confirmation
            var user = await _userManager.FindByEmailAsync(request.Email);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmLink = Url.Action(
                nameof(ConfirmEmail), "Auth",
                new { userId = user.Id, token },
                Request.Scheme);

            await _emailService.SendEmailAsync(
                request.Email,
                "Xác nhận Email",
                $"Vui lòng nhấp vào <a href=\"{confirmLink}\">đây</a> để xác nhận tài khoản.");

            return Ok(result);
        }

        // 2) Xác nhận Email
        [HttpGet("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(Guid userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return BadRequest("Người dùng không tồn tại.");

            var res = await _userManager.ConfirmEmailAsync(user, token);
            if (!res.Succeeded)
                return BadRequest("Xác nhận thất bại.");

            return Ok("Xác nhận email thành công.");
        }

        // 3) Login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            var result = await _userService.LoginAsync(request);
            return Ok(result);
        }

        // 4) Forgot Password → Gửi link reset
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDTO req)
        {
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                return BadRequest("Email không hợp lệ hoặc chưa xác thực.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action(
                nameof(ResetPassword), "Auth",
                new { email = req.Email, token },
                Request.Scheme);

            await _emailService.SendPasswordResetEmailAsync(req.Email, resetLink);
            return Ok("Đã gửi email đặt lại mật khẩu.");
        }

        // 5) Reset Password
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDTO req)
        {
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return BadRequest("Người dùng không tồn tại.");

            var res = await _userManager.ResetPasswordAsync(user, req.Token, req.NewPassword);
            if (!res.Succeeded)
                return BadRequest(res.Errors);

            await _emailService.SendPasswordChangedEmailAsync(req.Email);
            return Ok("Đổi mật khẩu thành công.");
        }

        // 6) Send 2FA Code qua email
        [HttpPost("send-2fa-code")]
        [Authorize]
        public async Task<IActionResult> Send2FACode()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            // Tạo mã 2FA
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailService.Send2FAEmailAsync(user.Email, code);

            return Ok("Mã 2FA đã được gửi.");
        }

        // 7) Change Password (có sẵn)
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var response = await _userService.ChangePasswordAsync(request);
            if (!response.IsSuccess)
                return BadRequest(response);

            // Gửi email xác nhận thay đổi mật khẩu
            var user = await _userManager.GetUserAsync(User);
            var email = await _userManager.GetEmailAsync(user);
            await _emailService.SendPasswordChangedEmailAsync(email);

            return Ok(response);
        }

        // 8) Refresh & Revoke tokens (không đổi)
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request) =>
            Ok(await _userService.RefreshTokenAsync(request));

        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest request)
        {
            var response = await _userService.RevokeRefreshTokenAsync(request);
            return response.IsSuccess ? Ok(response) : BadRequest(response);
        }

        // 9) Get Current User
        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser() =>
            Ok(await _userService.GetCurrentUserAsync());

        // 10) Google OAuth2 (giữ nguyên)
        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var props = _signInManager.ConfigureExternalAuthenticationProperties(
                "Google", Url.Action("GoogleResponse", "Auth"));
            return new ChallengeResult("Google", props);
        }

        [HttpGet("google-response")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await _externalAuthService.ProcessGoogleLoginAsync();
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
    }

}