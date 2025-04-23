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

        public UserService(UserManager<User> userManager, ITokenService tokenService, ICurrentUserService currentUserService, IUnitOfWork unitOfWork, ILogger<UserService> logger)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        public Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest req) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                if (await _userManager.ExistsByEmailAsync(req.Email))
                    return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

                _logger.LogInformation("Register user: {Email}", req.Email);

                // --- Tạo user mới
                var user = req.ToDomainUser();
                user.UserName = req.GenerateUsername();

                var createRes = await _userManager.CreateUserAsync(user, req.Password);
                if (!createRes.Succeeded)
                    return ApiResult<UserResponse>.Failure(createRes.ErrorMessage);

                // Gán role mặc định
                await _userManager.AddDefaultRoleAsync(user);

                var dto = await user.BuildResponseAsync(_userManager); 
                return ApiResult<UserResponse>.Success(dto);
            });

        public Task<ApiResult<UserResponse>> AdminRegisterAsync(AdminCreateUserRequest req) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                if (!_currentUserService.IsAdmin())
                    return ApiResult<UserResponse>.Failure("Forbidden: Only Admins can register users");

                if (await _userManager.ExistsByEmailAsync(req.Email))
                    return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

                _logger.LogInformation("AdminRegister user: {Email}", req.Email);
                var user = req.ToDomainUser();
                user.UserName = req.GenerateUsername();

                var create = await _userManager.CreateUserAsync(user, req.Password);
                if (!create.Succeeded)
                    return ApiResult<UserResponse>.Failure(create.ErrorMessage);

                await _userManager.AddRolesAsync(user, req.Roles);
                var token = await _tokenService.GenerateToken(user);

                return ApiResult<UserResponse>.Success(
                    await user.BuildResponseAsync(_userManager, token.Data));
            });

        public async Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest req)
        {
            _logger.LogInformation("Login attempt: {Email}", req.Email);

            // 1) Lấy user theo email
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");

            // 2) Kiểm tra mật khẩu
            if (!await _userManager.CheckPasswordAsync(user, req.Password))
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");

            // 3) Kiểm tra email đã xác thực
            if (!await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<UserResponse>.Failure("Vui lòng xác nhận email trước khi đăng nhập.");

            // 4) Kiểm tra lockout
            if (await _userManager.IsLockedOutAsync(user))
                return ApiResult<UserResponse>.Failure("Tài khoản bị khóa.");

            // 5) Đặt lại số lần thất bại
            await _userManager.ResetAccessFailedAsync(user);

            // 6) Sinh access + refresh token
            var tokenResult = await _tokenService.GenerateToken(user);
            var accessToken = tokenResult.Data;
            var refreshToken = _tokenService.GenerateRefreshToken();
            await _userManager.SetAuthenticationTokenAsync(user,
                loginProvider: "MyApp", tokenName: "RefreshToken", tokenValue: refreshToken);

            // 7) Trả về DTO
            var dto = await user.BuildResponseAsync(_userManager, accessToken, refreshToken);
            return ApiResult<UserResponse>.Success(dto);
        }

        public async Task<ApiResult<UserResponse>> GetByIdAsync(Guid id)
        {
            var user = await _userManager.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            return ApiResult<UserResponse>.Success(
                await user.BuildResponseAsync(_userManager));
        }

        public async Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync()
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (user == null)
                return ApiResult<CurrentUserResponse>.Failure("User not found");

            var token = await _tokenService.GenerateToken(user);
            return ApiResult<CurrentUserResponse>.Success(
                user.BuildCurrentResponse(token.Data));
        }

        public async Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (!await _userManager.ValidateRefreshTokenAsync(user, req.RefreshToken))
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");

            var token = await _tokenService.GenerateToken(user);
            return ApiResult<CurrentUserResponse>.Success(
                user.BuildCurrentResponse(token.Data));
        }

        public async Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshTokenAsync(RefreshTokenRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (!await _userManager.ValidateRefreshTokenAsync(user, req.RefreshToken))
                return ApiResult<RevokeRefreshTokenResponse>.Failure("Invalid refresh token");

            var rem = await _userManager.RemoveRefreshTokenAsync(user);
            if (!rem.Succeeded)
                return ApiResult<RevokeRefreshTokenResponse>.Failure(rem.ErrorMessage);

            return ApiResult<RevokeRefreshTokenResponse>.Success(
                new RevokeRefreshTokenResponse { Message = "Revoked" });
        }

        public async Task<ApiResult<string>> ChangePasswordAsync(ChangePasswordRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            var res = await _userManager.ChangeUserPasswordAsync(user, req.OldPassword, req.NewPassword);
            if (!res.Succeeded)
                return ApiResult<string>.Failure(res.ErrorMessage);

            await _userManager.UpdateSecurityStampAsync(user);
            return ApiResult<string>.Success("Password changed");
        }

        public Task<ApiResult<UserResponse>> UpdateAsync(Guid id, UpdateUserRequest req) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var user = await _userManager.FindByIdAsync(id.ToString());
                if (user == null)
                    return ApiResult<UserResponse>.Failure("User not found");

                req.ApplyToDomain(user);
                user.UpdateAt = DateTime.UtcNow;

                if (req.Roles?.Any() == true && _currentUserService.IsAdmin())
                {
                    await _userManager.UpdateRolesAsync(user, req.Roles);
                }

                var upd = await _userManager.UpdateAsync(user);
                if (!upd.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", upd.Errors.Select(e => e.Description)));

                return ApiResult<UserResponse>.Success(
                    await user.BuildResponseAsync(_userManager));
            });

        public Task<ApiResult<UserResponse>> UpdateCurrentUserAsync(UpdateUserRequest req) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var uid = _currentUserService.GetUserId();
                var user = await _userManager.FindByIdAsync(uid);
                if (user == null)
                    return ApiResult<UserResponse>.Failure("User not found");

                req.ApplyToDomain(user);
                user.UpdateAt = DateTime.UtcNow;

                var upd = await _userManager.UpdateAsync(user);
                if (!upd.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", upd.Errors.Select(e => e.Description)));

                return ApiResult<UserResponse>.Success(
                    await user.BuildResponseAsync(_userManager));
            });

        public Task<ApiResult<UserResponse>> LockUserAsync(Guid id) =>
            ChangeLockoutAsync(id, true, DateTimeOffset.MaxValue);

        public Task<ApiResult<UserResponse>> UnlockUserAsync(Guid id) =>
            ChangeLockoutAsync(id, true, DateTimeOffset.UtcNow);

        private async Task<ApiResult<UserResponse>> ChangeLockoutAsync(Guid id, bool enable, DateTimeOffset until)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            var res = await _userManager.SetLockoutAsync(user, enable, until);
            if (!res.Succeeded)
                return ApiResult<UserResponse>.Failure(res.ErrorMessage);

            return ApiResult<UserResponse>.Success(
                await user.BuildResponseAsync(_userManager));
        }

        public Task<ApiResult<object>> DeleteUsersAsync(List<Guid> ids) =>
            _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                foreach (var id in ids)
                {
                    var user = await _userManager.FindByIdAsync(id.ToString());
                    if (user == null)
                        return ApiResult<object>.Failure($"User {id} not found");

                    var del = await _userManager.DeleteAsync(user);
                    if (!del.Succeeded)
                        return ApiResult<object>.Failure(
                            string.Join(", ", del.Errors.Select(e => e.Description)));
                }
                return ApiResult<object>.Success(null);
            });

        public async Task<UserResponse> CreateOrUpdateGoogleUserAsync(GoogleUserInfo info)
        {
            var user = await _userManager.FindByEmailAsync(info.Email);
            var isNew = user == null;

            if (isNew)
            {
                // Tạo mới user và gán role ngay lập tức
                user = info.ToDomainUser();
                var createRes = await _userManager.CreateUserAsync(user);
                if (!createRes.Succeeded)
                    return null; // hoặc handle error phù hợp

                await _userManager.AddDefaultRoleAsync(user);
            }
            else
            {
                // Đảm bảo user cũ cũng có role USER
                if (!await _userManager.IsInRoleAsync(user, "USER"))
                    await _userManager.AddDefaultRoleAsync(user);

                // Cập nhật thông tin từ Google nếu cần
                var updated = info.MergeGoogleInfo(user);
                if (updated)
                    await _userManager.UpdateAsync(user);
            }

            var token = await _tokenService.GenerateToken(user);
            var refresh = _tokenService.GenerateRefreshToken();
            await _userManager.SetRefreshTokenAsync(user, refresh);

            return await user.BuildResponseAsync(_userManager, token.Data, refresh);
        }

        public async Task<ApiResult<PagedList<UserDetailsDTO>>> GetUsersAsync(int page, int size)
        {
            var list = await _unitOfWork.UserRepository.GetUserDetailsAsync(page, size);
            return ApiResult<PagedList<UserDetailsDTO>>.Success(list);
        }
    }
}
