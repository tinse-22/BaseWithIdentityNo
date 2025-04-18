using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Services.Implementations
{
    public class ExternalAuthService : IExternalAuthService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly IUserService _userService;

        public ExternalAuthService(SignInManager<User> signInManager, IUserService userService)
        {
            _signInManager = signInManager;
            _userService = userService;
        }

        public async Task<ApiResult<UserResponse>> ProcessGoogleLoginAsync()
        {
            // Lấy thông tin login từ Google
            var result = await _signInManager.GetExternalLoginInfoAsync();
            if (result == null)
                return ApiResult<UserResponse>.Failure("Google login information not found");

            // Lấy email, tên từ claims
            var email = result.Principal.FindFirstValue(ClaimTypes.Email);
            var first = result.Principal.FindFirstValue(ClaimTypes.GivenName);
            var last = result.Principal.FindFirstValue(ClaimTypes.Surname);
            var info = new GoogleUserInfo { Email = email, FirstName = first, LastName = last };

            // Tạo hoặc cập nhật user, đồng thời gán role và sinh token
            var userResp = await _userService.CreateOrUpdateGoogleUserAsync(info);
            if (userResp == null)
                return ApiResult<UserResponse>.Failure("Cannot create or update Google user");

            return ApiResult<UserResponse>.Success(userResp);
        }
    }

}
