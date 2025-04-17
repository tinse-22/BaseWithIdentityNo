using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Services.Extensions;
using Services.Extensions.Mapers;

namespace Services.Implementations
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserService> _logger;

        public UserService(
            UserManager<User> userManager,
            ITokenService tokenService,
            ICurrentUserService currentUserService,
            IUnitOfWork unitOfWork,
            ILogger<UserService> logger)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        // 1. Đăng ký bình thường
        public Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest request) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                if (await _userManager.FindByEmailAsync(request.Email) != null)
                {
                    _logger.LogWarning("Attempt to register with existing email: {Email}", request.Email);
                    return ApiResult<UserResponse>.Failure("Email đã được sử dụng");
                }
                _logger.LogInformation("Register user: {Email}", request.Email);

                var newUser = new User
                {
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Email = request.Email,
                    Gender = request.Gender.ToString(),
                    CreateAt = DateTime.UtcNow,
                    UpdateAt = DateTime.UtcNow,
                    UserName = GenerateUsername(request.FirstName, request.LastName)
                };

                // Tạo user và gán role USER
                var cr = await _userManager.CreateAsync(newUser, request.Password).ConfigureAwait(false);
                if (!cr.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", cr.Errors.Select(e => e.Description)));

                var rr = await _userManager.AddToRoleAsync(newUser, "USER");
                if (!rr.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", rr.Errors.Select(e => e.Description)));

                // Tạo token và lưu refresh-token
                var tokenRes = await _tokenService.GenerateToken(newUser);
                var refreshToken = _tokenService.GenerateRefreshToken();
                await _userManager.SetAuthenticationTokenAsync(
                    newUser, "MyApp", "RefreshToken", refreshToken);

                var userResp = await newUser.ToUserResponseAsync(
                    _userManager, tokenRes.Data, refreshToken);
                return ApiResult<UserResponse>.Success(userResp);
            });

        // 2. Đăng ký bằng Admin
        public Task<ApiResult<UserResponse>> AdminRegisterAsync(AdminCreateUserRequest request) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                if (!_currentUserService.IsAdmin())
                    return ApiResult<UserResponse>.Failure("Forbidden: Only Admins can register users");
                _logger.LogInformation("AdminRegister user: {Email}", request.Email);
                if (await _userManager.FindByEmailAsync(request.Email) != null)
                    return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

                var newUser = new User
                {
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Email = request.Email,
                    Gender = request.Gender?.ToString(),
                    CreateAt = DateTime.UtcNow,
                    UpdateAt = DateTime.UtcNow,
                    UserName = GenerateUsername(request.FirstName, request.LastName)
                };

                var cr = await _userManager.CreateAsync(newUser, request.Password);
                if (!cr.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", cr.Errors.Select(e => e.Description)));

                var roles = request.Roles?.Any() == true
                    ? request.Roles
                    : new List<string> { "USER" };

                var rr = await _userManager.AddToRolesAsync(newUser, roles);
                if (!rr.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join("; ", rr.Errors.Select(e => e.Description)));

                var tokenRes = await _tokenService.GenerateToken(newUser);
                var userResp = await newUser.ToUserResponseAsync(
                    _userManager, tokenRes.Data);

                return ApiResult<UserResponse>.Success(userResp);
            });

        // 3. Đăng nhập
        public async Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest request)
        {
            _logger.LogInformation("Login attempt: {Email}", request.Email);
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                _logger.LogWarning("Invalid login for {Email}", request.Email);
                return ApiResult<UserResponse>.Failure("Invalid user or password");
            }

            if (await _userManager.IsLockedOutAsync(user))
                return ApiResult<UserResponse>.Failure("Account is locked");

            await _userManager.ResetAccessFailedCountAsync(user);
            var accessRes = await _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            await _userManager.SetAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken", refreshToken);

            var userResp = await user.ToUserResponseAsync(
                _userManager, accessRes.Data, refreshToken);
            return ApiResult<UserResponse>.Success(userResp);
        }

        // 4. Lấy theo ID
        public async Task<ApiResult<UserResponse>> GetByIdAsync(Guid id)
        {
            var user = await _userManager.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            var resp = await user.ToUserResponseAsync(_userManager);
            return ApiResult<UserResponse>.Success(resp);
        }

        // 5. Lấy current user
        public async Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync()
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id.ToString() == uid);
            if (user == null)
                return ApiResult<CurrentUserResponse>.Failure("User not found");

            var tokenRes = await _tokenService.GenerateToken(user);
            var resp = user.ToCurrentUserResponse(tokenRes.Data);
            return ApiResult<CurrentUserResponse>.Success(resp);
        }

        // 6. Refresh access token
        public async Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest request)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            var stored = await _userManager.GetAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken");
            if (stored != request.RefreshToken)
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");

            var accessRes = await _tokenService.GenerateToken(user);
            var resp = user.ToCurrentUserResponse(accessRes.Data);
            return ApiResult<CurrentUserResponse>.Success(resp);
        }

        // 7. Revoke refresh token
        public async Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshTokenAsync(RefreshTokenRequest request)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            var stored = await _userManager.GetAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken");
            if (stored != request.RefreshToken)
                return ApiResult<RevokeRefreshTokenResponse>.Failure("Invalid refresh token");

            var rem = await _userManager.RemoveAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken");
            if (!rem.Succeeded)
                return ApiResult<RevokeRefreshTokenResponse>.Failure(
                    string.Join(", ", rem.Errors.Select(e => e.Description)));

            return ApiResult<RevokeRefreshTokenResponse>.Success(
                new RevokeRefreshTokenResponse { Message = "Revoked" });
        }

        // 8. Đổi mật khẩu
        public async Task<ApiResult<string>> ChangePasswordAsync(ChangePasswordRequest request)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            var res = await _userManager.ChangePasswordAsync(
                user, request.OldPassword, request.NewPassword);
            if (!res.Succeeded)
                return ApiResult<string>.Failure(
                    string.Join(", ", res.Errors.Select(e => e.Description)));

            await _userManager.UpdateSecurityStampAsync(user);
            return ApiResult<string>.Success("Password changed");
        }

        // 9. Cập nhật user (Admin có thể thay role)
        public Task<ApiResult<UserResponse>> UpdateAsync(
            Guid id, UpdateUserRequest request) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var user = await _userManager.FindByIdAsync(id.ToString());
                if (user == null)
                    return ApiResult<UserResponse>.Failure("User not found");

                UpdateFields(user, request);
                user.UpdateAt = DateTime.UtcNow;

                if (request.Roles?.Any() == true &&
                    _currentUserService.IsAdmin())
                {
                    var oldRoles = await _userManager.GetRolesAsync(user);
                    await _userManager.RemoveFromRolesAsync(user, oldRoles);
                    await _userManager.AddToRolesAsync(user, request.Roles);
                }

                var upd = await _userManager.UpdateAsync(user);
                if (!upd.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", upd.Errors.Select(e => e.Description)));

                var resp = await user.ToUserResponseAsync(_userManager);
                return ApiResult<UserResponse>.Success(resp);
            });

        // 10. Cập nhật profile (không thay đổi role)
        public Task<ApiResult<UserResponse>> UpdateCurrentUserAsync(UpdateUserRequest request) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var uid = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(uid);
                if (user == null)
                    return ApiResult<UserResponse>.Failure("User not found");

                UpdateFields(user, request);
                user.UpdateAt = DateTime.UtcNow;

                var upd = await _userManager.UpdateAsync(user);
                if (!upd.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", upd.Errors.Select(e => e.Description)));

                var resp = await user.ToUserResponseAsync(_userManager);
                return ApiResult<UserResponse>.Success(resp);
            });

        // 11. Khóa/Mở khóa user
        public async Task<ApiResult<UserResponse>> LockUserAsync(Guid id) =>
            await ChangeLockoutAsync(id, true, DateTimeOffset.MaxValue);

        public async Task<ApiResult<UserResponse>> UnlockUserAsync(Guid id) =>
            await ChangeLockoutAsync(id, true, DateTimeOffset.UtcNow);

        private async Task<ApiResult<UserResponse>> ChangeLockoutAsync(
            Guid id, bool enable, DateTimeOffset until)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            await _userManager.SetLockoutEnabledAsync(user, enable);
            var res = await _userManager.SetLockoutEndDateAsync(user, until);
            if (!res.Succeeded)
                return ApiResult<UserResponse>.Failure(
                    string.Join(", ", res.Errors.Select(e => e.Description)));

            await _userManager.UpdateAsync(user);
            var resp = await user.ToUserResponseAsync(_userManager);
            return ApiResult<UserResponse>.Success(resp);
        }

        // 12. Xóa user đơn lẻ hoặc hàng loạt
        public Task<ApiResult<object>> DeleteUsersAsync(List<Guid> ids) =>
    _unitOfWork.ExecuteTransactionAsync(async () =>
    {
        foreach (var id in ids)
        {
            var usr = await _userManager.FindByIdAsync(id.ToString());
            if (usr == null)
                return ApiResult<object>.Failure($"User {id} not found");

            var dr = await _userManager.DeleteAsync(usr);
            if (!dr.Succeeded)
                return ApiResult<object>.Failure(
                    string.Join(", ", dr.Errors.Select(e => e.Description)));
        }
        return ApiResult<object>.Success(null);
    });

        // 13. Google OAuth
        public async Task<UserResponse> CreateOrUpdateGoogleUserAsync(
            GoogleUserInfo info)
        {
            var user = await _userManager.FindByEmailAsync(info.Email);
            var isNew = user == null;

            if (isNew)
            {
                user = new User
                {
                    UserName = info.Email,
                    Email = info.Email,
                    FirstName = info.FirstName,
                    LastName = info.LastName,
                    CreateAt = DateTime.UtcNow,
                    UpdateAt = DateTime.UtcNow
                };
                await _userManager.CreateAsync(user);
                await _userManager.AddToRoleAsync(user, "USER");
            }
            else
            {
                var changed = false;
                if (user.FirstName != info.FirstName)
                { user.FirstName = info.FirstName; changed = true; }
                if (user.LastName != info.LastName)
                { user.LastName = info.LastName; changed = true; }
                if (changed)
                {
                    user.UpdateAt = DateTime.UtcNow;
                    await _userManager.UpdateAsync(user);
                }
                if (!await _userManager.IsInRoleAsync(user, "USER"))
                    await _userManager.AddToRoleAsync(user, "USER");
            }

            var tokenRes = await _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            await _userManager.SetAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken", refreshToken);

            return await user.ToUserResponseAsync(
                _userManager, tokenRes.Data, refreshToken);
        }

        // 14. Lấy danh sách người dùng phân trang
        public async Task<ApiResult<PagedList<UserDetailsDTO>>> GetUsersAsync(
            int pageNumber, int pageSize)
        {
            var list = await _unitOfWork.UserRepository
                .GetUserDetailsAsync(pageNumber, pageSize);
            return ApiResult<PagedList<UserDetailsDTO>>.Success(list);
        }

        // Helper methods
        private static string GenerateUsername(string first, string last) =>
            $"{first}{last}{Guid.NewGuid():N}".ToLower();

        private static void UpdateFields(User user, UpdateUserRequest req)
        {
            if (!string.IsNullOrEmpty(req.FirstName)) user.FirstName = req.FirstName;
            if (!string.IsNullOrEmpty(req.LastName)) user.LastName = req.LastName;
            if (!string.IsNullOrEmpty(req.Email) &&
                new EmailAddressAttribute().IsValid(req.Email))
                user.Email = req.Email;
            if (!string.IsNullOrEmpty(req.PhoneNumbers))
                user.PhoneNumber = req.PhoneNumbers;
            if (!string.IsNullOrEmpty(req.Gender.ToString()))
                user.Gender = req.Gender.ToString();
        }
    }
}
