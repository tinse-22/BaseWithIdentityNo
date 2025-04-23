using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Services.Implementations
{
    public class ExternalAuthService : IExternalAuthService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly IUserService _userService;
        private readonly UserManager<User> _userManager;

        public ExternalAuthService(
            SignInManager<User> signInManager,
            IUserService userService,
            UserManager<User> userManager)
        {
            _signInManager = signInManager;
            _userService = userService;
            _userManager = userManager;
        }

        public async Task<ApiResult<UserResponse>> ProcessGoogleLoginAsync()
        {
            // 1) Lấy thông tin Google login
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return ApiResult<UserResponse>.Failure("Google login information not found");

            // 2) Đọc các claim cần thiết
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var first = info.Principal.FindFirstValue(ClaimTypes.GivenName);
            var last = info.Principal.FindFirstValue(ClaimTypes.Surname);

            // 3) Tạo hoặc cập nhật User thông qua UserService
            var googleInfo = new GoogleUserInfo
            {
                Email = email,
                FirstName = first,
                LastName = last
            };
            var userResp = await _userService.CreateOrUpdateGoogleUserAsync(googleInfo);
            if (userResp == null)
                return ApiResult<UserResponse>.Failure("Cannot create or update Google user");

            // 4) Tự động đánh dấu email đã được xác thực
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null && !user.EmailConfirmed)
            {
                user.EmailConfirmed = true;
                await _userManager.UpdateAsync(user);
            }

            // 5) Trả về kết quả cuối cùng (đã có token + refresh token)
            return ApiResult<UserResponse>.Success(userResp);
        }
    }
}
