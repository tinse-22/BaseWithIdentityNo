using System.Text;
using BusinessObjects.Common;
using DTOs.UserDTOs.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
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
        private readonly IConfiguration _configuration;

        public AuthController(IUserService userServices, SignInManager<User> signInManager,  IExternalAuthService externalAuthService, IEmailService emailService, UserManager<User> userManager, IConfiguration configuration)
        {
            _userService = userServices;
            _signInManager = signInManager;
            _externalAuthService = externalAuthService;
            _emailService = emailService;
            _userManager = userManager;
            _configuration = configuration;
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

        /// <summary>
        /// Gửi email đặt lại mật khẩu. 
        /// Frontend URL được cấu hình trong appsettings.json (key: Frontend:ResetPasswordUri)
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDTO req)
        {
            if (!ModelState.IsValid)
                return BadRequest("Dữ liệu không hợp lệ.");

            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                // Không tiết lộ chi tiết: luôn trả về Ok để tránh dò email
                return Ok("Nếu email hợp lệ, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.");

            // 1) Tạo token và mã hóa bằng Base64 URL
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var tokenBytes = Encoding.UTF8.GetBytes(token);
            var encodedToken = WebEncoders.Base64UrlEncode(tokenBytes);

            // 2) Lấy URL frontend từ cấu hình
            var resetPasswordUri = _configuration["Frontend:ResetPasswordUri"];
            // Ví dụ: https://yourfrontend.com/reset-password
            var resetLink = $"{resetPasswordUri}?email={Uri.EscapeDataString(req.Email)}&token={encodedToken}";

            // 3) Gửi email
            await _emailService.SendPasswordResetEmailAsync(req.Email, resetLink);

            return Ok("Nếu email hợp lệ, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.");
        }

        /// <summary>
        /// Xử lý đặt lại mật khẩu. 
        /// Nhận payload từ frontend gồm email, token đã mã hóa và mật khẩu mới.
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDTO req)
        {
            if (!ModelState.IsValid)
                return BadRequest("Dữ liệu không hợp lệ.");

            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return BadRequest("Yêu cầu không hợp lệ.");

            // Giải mã token
            string decodedToken;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(req.Token);
                decodedToken = Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                return BadRequest("Token không hợp lệ.");
            }

            // Đặt lại mật khẩu
            var result = await _userManager.ResetPasswordAsync(user, decodedToken, req.NewPassword);
            if (!result.Succeeded)
            {
                // Có thể log chi tiết result.Errors ở server
                return BadRequest("Đặt lại mật khẩu thất bại. Vui lòng thử lại.");
            }

            // Gửi email xác nhận mật khẩu đã thay đổi
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

        /// <summary>
        /// Bước 1: Redirect tới Google để lấy authorization code
        /// </summary>
        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action(nameof(GoogleResponse), "Auth");
            var props = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return Challenge(props, "Google");
        }

        /// <summary>
        /// Bước 2: Google callback về -- thực hiện tạo/cập nhật user, bật EmailConfirmed, sinh JWT
        /// </summary>
        [HttpGet("google-response")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            // Lấy thông tin từ Google
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return BadRequest(ApiResult<UserResponse>.Failure("Không lấy được thông tin Google login."));

            // Dùng service để xử lý toàn bộ flow
            var result = await _externalAuthService.ProcessGoogleLoginAsync();
            if (!result.IsSuccess)
                return BadRequest(result);

            // Trả về user + accessToken + refreshToken
            return Ok(result);
        }
    }

}