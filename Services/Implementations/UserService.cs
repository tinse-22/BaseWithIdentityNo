using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;


namespace Services.Implementations
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserService> _logger;
        private readonly IEmailQueueService _emailQueueService; // Added for queue-based email sending
        private readonly IConfiguration _configuration;

        public UserService(
            UserManager<User> userManager,
            ITokenService tokenService,
            ICurrentUserService currentUserService,
            IUnitOfWork unitOfWork,
            ILogger<UserService> logger,
            IEmailQueueService emailQueueService, 
            IConfiguration configuration)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _unitOfWork = unitOfWork;
            _logger = logger;
            _emailQueueService = emailQueueService;
            _configuration = configuration;
        }

        public async Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest req)
        {
            var result = await _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                if (await _userManager.ExistsByEmailAsync(req.Email))
                    return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

                var user = req.ToDomainUser();
                user.UserName = req.GenerateUsername();

                var createRes = await _userManager.CreateUserAsync(user, req.Password);
                if (!createRes.Succeeded)
                    return ApiResult<UserResponse>.Failure(createRes.ErrorMessage);

                await _userManager.AddDefaultRoleAsync(user);
                return ApiResult<UserResponse>.Success(await user.BuildResponseAsync(_userManager));
            });

            if (result.IsSuccess)
            {
                var user = await _userManager.FindByEmailAsync(req.Email);
                if (user != null)
                {
                    // Queue emails instead of sending synchronously
                    _ = _emailQueueService.QueueEmailAsync(req.Email, "Chào mừng", "Chào mừng bạn đến với ứng dụng!");
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmLink = $"{_configuration["Frontend:ConfirmEmailUri"]}?userId={user.Id}&token={token}";
                    _ = _emailQueueService.QueueEmailAsync(req.Email, "Xác nhận Email", $"Vui lòng nhấp vào <a href=\"{confirmLink}\">đây</a> để xác nhận tài khoản.");
                }
            }
            return result;
        }

        public async Task<ApiResult<string>> ConfirmEmailAsync(Guid userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return ApiResult<string>.Failure("Người dùng không tồn tại.");

            var res = await _userManager.ConfirmEmailAsync(user, token);
            return res.Succeeded ? ApiResult<string>.Success("Xác nhận email thành công.") : ApiResult<string>.Failure("Xác nhận thất bại.");
        }

        public async Task<ApiResult<string>> ResendConfirmationEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<string>.Success("Nếu email hợp lệ và chưa được xác thực, bạn sẽ nhận email xác thực.");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var link = $"{_configuration["Frontend:ConfirmEmailUri"]}?userId={user.Id}&token={token}";
            _ = _emailQueueService.QueueEmailAsync(user.Email, "Xác nhận Email - Gửi lại", $"Vui lòng nhấp <a href=\"{link}\">vào đây</a> để xác nhận tài khoản.");
            return ApiResult<string>.Success("Email xác thực đã được gửi lại.");
        }

        public async Task<ApiResult<string>> InitiatePasswordResetAsync(ForgotPasswordRequestDTO request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<string>.Success("Nếu email hợp lệ, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = $"{_configuration["Frontend:ResetPasswordUri"]}?email={Uri.EscapeDataString(request.Email)}&token={encodedToken}";
            _ = _emailQueueService.QueueEmailAsync(request.Email, "Đặt lại mật khẩu", $"Nhấp <a href=\"{resetLink}\">vào đây</a> để đặt lại mật khẩu.");
            return ApiResult<string>.Success("Nếu email hợp lệ, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.");
        }

        public async Task<ApiResult<string>> ResetPasswordAsync(ResetPasswordRequestDTO request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return ApiResult<string>.Failure("Yêu cầu không hợp lệ.");

            string token;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(request.Token);
                token = Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                return ApiResult<string>.Failure("Token không hợp lệ.");
            }

            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
            if (!result.Succeeded)
                return ApiResult<string>.Failure("Đặt lại mật khẩu thất bại. Vui lòng thử lại.");

            _ = _emailQueueService.QueueEmailAsync(request.Email, "Mật khẩu đã thay đổi", "Mật khẩu của bạn đã được thay đổi thành công.");
            return ApiResult<string>.Success("Đổi mật khẩu thành công.");
        }

        public async Task<ApiResult<string>> Send2FACodeAsync()
        {
            var userId = _currentUserService.GetUserId();
            if (userId == null)
                return ApiResult<string>.Failure("Người dùng không tồn tại.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return ApiResult<string>.Failure("Người dùng không tồn tại.");

            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            _ = _emailQueueService.QueueEmailAsync(user.Email, "Mã xác thực 2FA", $"Mã của bạn là: {code}");
            return ApiResult<string>.Success("Mã 2FA đã được gửi.");
        }

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

            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");

            if (!await _userManager.CheckPasswordAsync(user, req.Password))
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<UserResponse>.Failure("Vui lòng xác nhận email trước khi đăng nhập.");

            if (await _userManager.IsLockedOutAsync(user))
                return ApiResult<UserResponse>.Failure("Tài khoản bị khóa.");

            await _userManager.ResetAccessFailedAsync(user);

            var tokenResult = await _tokenService.GenerateToken(user);
            var accessToken = tokenResult.Data;
            var refreshToken = _tokenService.GenerateRefreshToken();
            await _userManager.SetAuthenticationTokenAsync(user,
                loginProvider: "MyApp", tokenName: "RefreshToken", tokenValue: refreshToken);

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
                user = info.ToDomainUser();
                var createRes = await _userManager.CreateUserAsync(user);
                if (!createRes.Succeeded)
                    return null;

                await _userManager.AddDefaultRoleAsync(user);
            }
            else
            {
                if (!await _userManager.IsInRoleAsync(user, "USER"))
                    await _userManager.AddDefaultRoleAsync(user);

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