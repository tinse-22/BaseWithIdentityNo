using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace BaseIdentity.Application.Services
{
    public class ExternalAuthService : IExternalAuthService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;

        public ExternalAuthService(
            SignInManager<User> signInManager,
            UserManager<User> userManager,
            ITokenService tokenService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        public async Task<ApiResult<string>> ProcessGoogleLoginAsync()
        {
            // Lấy thông tin external login từ Google
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return ApiResult<string>.Failure("Không lấy được thông tin từ Google.");
            }

            // Thử đăng nhập bằng external login
            var signInResult = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider,
                info.ProviderKey,
                isPersistent: false);

            User user = null;
            if (!signInResult.Succeeded)
            {
                // Lấy email từ thông tin external
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                {
                    return ApiResult<string>.Failure("Email không tồn tại trong thông tin Google.");
                }

                // Kiểm tra xem user đã tồn tại hay chưa
                user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    // Tạo user mới nếu chưa tồn tại
                    user = new User
                    {
                        UserName = email,
                        Email = email
                    };

                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        var errorMsg = string.Join(", ", createResult.Errors.Select(e => e.Description));
                        return ApiResult<string>.Failure(errorMsg);
                    }
                }

                // Thêm external login cho user nếu chưa có
                var addLoginResult = await _userManager.AddLoginAsync(user, info);
                if (!addLoginResult.Succeeded)
                {
                    var errorMsg = string.Join(", ", addLoginResult.Errors.Select(e => e.Description));
                    return ApiResult<string>.Failure(errorMsg);
                }

                // Đăng nhập user
                await _signInManager.SignInAsync(user, isPersistent: false);
            }
            else
            {
                // Nếu đăng nhập external thành công, lấy user đã liên kết
                user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (user == null)
                {
                    return ApiResult<string>.Failure("Không tìm thấy user liên kết với thông tin đăng nhập Google.");
                }
            }

            // Sinh token JWT cho user
            var tokenResult = await _tokenService.GenerateToken(user);
            return tokenResult;
        }
    }

}
