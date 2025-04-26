using System.Net;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Repositories.Interfaces;

namespace Services.Implementations
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserService> _logger;
        private readonly IEmailQueueService _emailQueueService;
        private readonly string _confirmEmailUri;
        private readonly string _resetPasswordUri;
        private readonly IUserRepository _userRepository;

        public UserService(
            UserManager<User> userManager,
            ITokenService tokenService,
            ICurrentUserService currentUserService,
            IUnitOfWork unitOfWork,
            ILogger<UserService> logger,
            IEmailQueueService emailQueueService,
            IConfiguration configuration,
            IUserRepository userRepository)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _unitOfWork = unitOfWork;
            _logger = logger;
            _emailQueueService = emailQueueService;
            _confirmEmailUri = configuration["Frontend:ConfirmEmailUri"];
            _resetPasswordUri = configuration["Frontend:ResetPasswordUri"];
            _userRepository = userRepository;
        }

        public async Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest req)
        {
            if (await _userRepository.ExistsByEmailAsync(req.Email))
                return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

            var result = await _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var user = UserMappings.ToDomainUser(req);

                var createRes = await _userManager.CreateUserAsync(user, req.Password);
                if (!createRes.Succeeded)
                    return ApiResult<UserResponse>.Failure(createRes.ErrorMessage);

                await _userManager.AddDefaultRoleAsync(user);
                return ApiResult<UserResponse>.Success(await UserMappings.ToUserResponseAsync(user, _userManager));
            });

            if (result.IsSuccess)
            {
                try
                {
                    await SendWelcomeEmailsAsync(req.Email);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Không thể gửi email chào mừng cho {Email}", req.Email);
                }
            }
            return result;
        }

        private async Task SendWelcomeEmailsAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return;

            // Queue email chào mừng
            var welcomeTask = _emailQueueService.QueueEmailAsync(
                email,
                "Chào mừng",
                "Chào mừng bạn đến với ứng dụng!"
            );

            // Sinh token và encode
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebUtility.UrlEncode(token);  // ✅ Đã encode đúng :contentReference[oaicite:5]{index=5}
            var confirmLink = $"{_confirmEmailUri}?userId={user.Id}&token={encodedToken}";

            // Queue email xác nhận
            var confirmationTask = _emailQueueService.QueueEmailAsync(
                email,
                "Xác nhận Email",
                $"Vui lòng nhấp vào <a href=\"{confirmLink}\">đây</a> để xác nhận tài khoản."
            );

            await Task.WhenAll(welcomeTask, confirmationTask);
        }


        public async Task<ApiResult<string>> ConfirmEmailAsync(Guid userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return ApiResult<string>.Failure("Người dùng không tồn tại.");

            var res = await _userManager.ConfirmEmailAsync(user, token);
            return res.Succeeded
                ? ApiResult<string>.Success("Xác nhận email thành công.")
                : ApiResult<string>.Failure("Xác nhận thất bại.");
        }

        public async Task<ApiResult<string>> ResendConfirmationEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<string>.Success("Nếu email hợp lệ và chưa được xác thực, bạn sẽ nhận email xác thực.");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var link = $"{_confirmEmailUri}?userId={user.Id}&token={token}";
            await _emailQueueService.QueueEmailAsync(user.Email, "Xác nhận Email - Gửi lại",
                $"Vui lòng nhấp <a href=\"{link}\">vào đây</a> để xác nhận tài khoản.");

            return ApiResult<string>.Success("Email xác thực đã được gửi lại.");
        }

        public async Task<ApiResult<string>> InitiatePasswordResetAsync(ForgotPasswordRequestDTO request)
        {
            var genericResponse = ApiResult<string>.Success(
                "Nếu email hợp lệ, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.");

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                return genericResponse;

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = $"{_resetPasswordUri}?email={Uri.EscapeDataString(request.Email)}&token={encodedToken}";

            await _emailQueueService.QueueEmailAsync(request.Email, "Đặt lại mật khẩu",
                $"Nhấp <a href=\"{resetLink}\">vào đây</a> để đặt lại mật khẩu.");

            return genericResponse;
        }

        public async Task<ApiResult<string>> ResetPasswordAsync(ResetPasswordRequestDTO request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return ApiResult<string>.Failure("Yêu cầu không hợp lệ.");

            string token;
            try
            {
                token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
            }
            catch
            {
                return ApiResult<string>.Failure("Token không hợp lệ.");
            }

            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
            if (!result.Succeeded)
                return ApiResult<string>.Failure("Đặt lại mật khẩu thất bại. Vui lòng thử lại.");

            await _emailQueueService.QueueEmailAsync(request.Email, "Mật khẩu đã thay đổi",
                "Mật khẩu của bạn đã được thay đổi thành công.");

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
            await _emailQueueService.QueueEmailAsync(user.Email, "Mã xác thực 2FA", $"Mã của bạn là: {code}");

            return ApiResult<string>.Success("Mã 2FA đã được gửi.");
        }

        public async Task<ApiResult<UserResponse>> AdminRegisterAsync(AdminCreateUserRequest req)
        {
            if (!_currentUserService.IsAdmin())
                return ApiResult<UserResponse>.Failure("Forbidden: Only Admins can register users");

            if (await _userRepository.ExistsByEmailAsync(req.Email))
                return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

            _logger.LogInformation("AdminRegister user: {Email}", req.Email);

            return await _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                var user = UserMappings.ToDomainUser(req);

                var create = await _userManager.CreateUserAsync(user, req.Password);
                if (!create.Succeeded)
                    return ApiResult<UserResponse>.Failure(create.ErrorMessage);

                await _userManager.AddRolesAsync(user, req.Roles);
                var token = await _tokenService.GenerateToken(user);

                return ApiResult<UserResponse>.Success(
                    await UserMappings.ToUserResponseAsync(user, _userManager, token.Data));
            });
        }

        public async Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest req)
        {
            _logger.LogInformation("Login attempt: {Email}", req.Email);

            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");

            if (!await _userManager.CheckPasswordAsync(user, req.Password))
            {
                await _userManager.AccessFailedAsync(user);
                return ApiResult<UserResponse>.Failure("Email hoặc mật khẩu không đúng.");
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return ApiResult<UserResponse>.Failure("Vui lòng xác nhận email trước khi đăng nhập.");

            if (await _userManager.IsLockedOutAsync(user))
                return ApiResult<UserResponse>.Failure("Tài khoản bị khóa.");

            await _userManager.ResetAccessFailedAsync(user);

            // Thực hiện tuần tự các tác vụ
            var token = await _tokenService.GenerateToken(user); // Sinh token trước
            var refreshToken = _tokenService.GenerateRefreshToken(); // Sinh refresh token
            await _userManager.SetAuthenticationTokenAsync(user, "MyApp", "RefreshToken", refreshToken); // Lưu refresh token

            var userResponse = await UserMappings.ToUserResponseAsync(user, _userManager, token.Data, refreshToken);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<UserResponse>> GetByIdAsync(Guid id)
        {
            var userDetails = await _userRepository.GetUserDetailsByIdAsync(id);
            if (userDetails == null)
                return ApiResult<UserResponse>.Failure("User not found");

            return ApiResult<UserResponse>.Success(
                await UserMappings.ToUserResponseAsync(userDetails, _userManager));
        }

        public async Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync()
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (user == null)
                return ApiResult<CurrentUserResponse>.Failure("User not found");

            var token = await _tokenService.GenerateToken(user);
            return ApiResult<CurrentUserResponse>.Success(
                UserMappings.ToCurrentUserResponse(user, token.Data));
        }

        public async Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (user == null || !await _userManager.ValidateRefreshTokenAsync(user, req.RefreshToken))
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");

            var token = await _tokenService.GenerateToken(user);
            return ApiResult<CurrentUserResponse>.Success(
                UserMappings.ToCurrentUserResponse(user, token.Data));
        }

        public async Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshTokenAsync(RefreshTokenRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (user == null || !await _userManager.ValidateRefreshTokenAsync(user, req.RefreshToken))
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
            if (user == null)
                return ApiResult<string>.Failure("User not found");

            var res = await _userManager.ChangeUserPasswordAsync(user, req.OldPassword, req.NewPassword);
            if (!res.Succeeded)
                return ApiResult<string>.Failure(res.ErrorMessage);

            await _userManager.UpdateSecurityStampAsync(user);
            return ApiResult<string>.Success("Password changed");
        }

        public async Task<ApiResult<UserResponse>> UpdateAsync(Guid id, UpdateUserRequest req)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            return await _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                UserMappings.ApplyUpdate(req, user);
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
                    await UserMappings.ToUserResponseAsync(user, _userManager));
            });
        }

        public async Task<ApiResult<UserResponse>> UpdateCurrentUserAsync(UpdateUserRequest req)
        {
            var uid = _currentUserService.GetUserId();
            var user = await _userManager.FindByIdAsync(uid);
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found");

            return await _unitOfWork.ExecuteTransactionAsync(async () =>
            {
                UserMappings.ApplyUpdate(req, user);
                user.UpdateAt = DateTime.UtcNow;

                var upd = await _userManager.UpdateAsync(user);
                if (!upd.Succeeded)
                    return ApiResult<UserResponse>.Failure(
                        string.Join(", ", upd.Errors.Select(e => e.Description)));

                return ApiResult<UserResponse>.Success(
                    await UserMappings.ToUserResponseAsync(user, _userManager));
            });
        }

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
                await UserMappings.ToUserResponseAsync(user, _userManager));
        }

        public async Task<ApiResult<object>> DeleteUsersAsync(List<Guid> ids)
        {
            if (ids == null || !ids.Any())
                return ApiResult<object>.Success(null);

            return await _unitOfWork.ExecuteTransactionAsync(async () =>
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
        }

        public async Task<UserResponse> CreateOrUpdateGoogleUserAsync(GoogleUserInfo info)
        {
            var user = await _userManager.FindByEmailAsync(info.Email);
            var isNew = user == null;

            if (isNew)
            {
                user = UserMappings.ToDomainUser(info);
                var createRes = await _userManager.CreateUserAsync(user);
                if (!createRes.Succeeded)
                    return null;

                await _userManager.AddDefaultRoleAsync(user);
            }
            else
            {
                var tasks = new List<Task>(2);

                if (!await _userManager.IsInRoleAsync(user, "USER"))
                    tasks.Add(_userManager.AddDefaultRoleAsync(user));

                if (UserMappings.MergeGoogleInfo(info, user))
                    tasks.Add(_userManager.UpdateAsync(user));

                if (tasks.Any())
                    await Task.WhenAll(tasks);
            }

            var tokenTask = _tokenService.GenerateToken(user);
            var refresh = _tokenService.GenerateRefreshToken();

            await Task.WhenAll(
                tokenTask,
                _userManager.SetRefreshTokenAsync(user, refresh)
            );

            return await UserMappings.ToUserResponseAsync(user, _userManager, tokenTask.Result.Data, refresh);
        }

        public async Task<ApiResult<PagedList<UserDetailsDTO>>> GetUsersAsync(int page, int size)
        {
            var list = await _userRepository.GetUserDetailsAsync(page, size);
            return ApiResult<PagedList<UserDetailsDTO>>.Success(list);
        }
    }
}