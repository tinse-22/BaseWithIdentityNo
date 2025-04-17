using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BaseIdentity.Application.Services
{
    public class UserService : IUserService
    {
        private readonly ITokenService _tokenServices;
        private readonly ICurrentUserService _currentUserService;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<UserService> _logger;
        private readonly IUnitOfWork _unitOfWork;

        public UserService(
            ITokenService tokenServices,
            ICurrentUserService currentUserService,
            UserManager<User> userManager,
            ILogger<UserService> logger,
            IUnitOfWork unitOfWork)
        {
            _tokenServices = tokenServices;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _logger = logger;
            _unitOfWork = unitOfWork;
        }
        public async Task<ApiResult<UserResponse>> AdminRegisterAsync(AdminCreateUserRequest request)
        {
            // 1. Kiểm tra email tồn tại
            if (await _userManager.FindByEmailAsync(request.Email) != null)
                return ApiResult<UserResponse>.Failure("Email đã được sử dụng");

            // 2. Khởi tạo User mới
            var newUser = new User
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                UserName = GenerateUserName(request.FirstName ?? "", request.LastName ?? ""),
                Gender = request.Gender?.ToString(),
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow
            };

            using var tx = await _unitOfWork.BeginTransactionAsync();
            try
            {
                // 3. Tạo tài khoản với mật khẩu
                var createResult = await _userManager.CreateAsync(newUser, request.Password);
                if (!createResult.Succeeded)
                    return ApiResult<UserResponse>.Failure(string.Join(", ", createResult.Errors.Select(e => e.Description)));

                // 4. Gán role: nếu Roles null hoặc rỗng → gán "USER"
                var roles = request.Roles != null && request.Roles.Any()
                            ? request.Roles
                            : new List<string> { "USER" };

                var roleRes = await _userManager.AddToRolesAsync(newUser, roles);
                if (!roleRes.Succeeded)
                {
                    var allErrors = string.Join("; ", roleRes.Errors.Select(e => e.Description));
                    return ApiResult<UserResponse>.Failure(allErrors);
                }

                await tx.CommitAsync();
            }
            catch (Exception ex)
            {
                await tx.RollbackAsync();
                _logger.LogError(ex, "AdminRegisterAsync failed for {Email}", request.Email);
                return ApiResult<UserResponse>.Failure("Lỗi nội bộ, vui lòng thử lại");
            }

            // 5. Tạo token và trả về
            var token = await _tokenServices.GenerateToken(newUser);
            var userResp = await MapUserToUserResponseAsync(newUser,
                                token.IsSuccess ? token.Data : null);
            return ApiResult<UserResponse>.Success(userResp);
        }


        public async Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Registering user with email: {Email}", request.Email);

            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogInformation("Email already exists: {Email}", request.Email);
                return ApiResult<UserResponse>.Failure("Email already exists");
            }

            var newUser = new User
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                Gender = request.Gender.ToString(),
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow,
                UserName = GenerateUserName(request.FirstName ?? string.Empty, request.LastName ?? string.Empty)

            };

            using (var transaction = await _unitOfWork.BeginTransactionAsync())
            {
                try
                {
                    var createResult = await _userManager.CreateAsync(newUser, request.Password);
                    if (!createResult.Succeeded)
                    {
                        _logger.LogWarning("User creation failed: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                        return ApiResult<UserResponse>.Failure(string.Join(", ", createResult.Errors.Select(e => e.Description)));
                    }

                    var roleResult = await _userManager.AddToRoleAsync(newUser, "USER");
                    if (!roleResult.Succeeded)
                    {
                        _logger.LogWarning("Role assignment failed: {Errors}", string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                        return ApiResult<UserResponse>.Failure(string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                    }

                    await transaction.CommitAsync();
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError(ex, "Error during user registration for email: {Email}", request.Email);
                    throw;
                }
            }

            _logger.LogInformation("User created successfully: {Email}", newUser.Email);
            var tokenResult = await _tokenServices.GenerateToken(newUser);
            var userResponse = await MapUserToUserResponseAsync(newUser, tokenResult.IsSuccess ? tokenResult.Data : null);
            return ApiResult<UserResponse>.Success(userResponse);
        }
        public async Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest request)
        {
            if (request == null)
            {
                _logger.LogWarning("Login request is null");
                return ApiResult<UserResponse>.Failure("Invalid request");
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogInformation("Login failed: User not found for email {Email}", request.Email);
                return ApiResult<UserResponse>.Failure("Invalid user or password");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogInformation("Account locked for user: {Email}", user.Email);
                return ApiResult<UserResponse>.Failure("Your account is locked due to multiple failed login attempts.");
            }

            var checkPasswordResult = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!checkPasswordResult)
            {
                await _userManager.AccessFailedAsync(user);
                _logger.LogInformation("Invalid password for user: {Email}", user.Email);
                return ApiResult<UserResponse>.Failure("Invalid user or password");
            }

            await _userManager.ResetAccessFailedCountAsync(user);
            var accessTokenResult = await _tokenServices.GenerateToken(user);

            // Tạo refresh token (plain text)
            var refreshToken = _tokenServices.GenerateRefreshToken();

            // Lưu refresh token vào bảng UserTokens thông qua Identity API
            var setTokenResult = await _userManager.SetAuthenticationTokenAsync(
                user,
                "MyApp",          // LoginProvider tùy chỉnh
                "RefreshToken",   // Tên token
                refreshToken      // Giá trị token plain text
            );

            if (!setTokenResult.Succeeded)
            {
                _logger.LogWarning("Failed to set refresh token: {Errors}",
                    string.Join(", ", setTokenResult.Errors.Select(e => e.Description)));
                return ApiResult<UserResponse>.Failure(string.Join(", ", setTokenResult.Errors.Select(e => e.Description)));
            }

            var userResponse =await MapUserToUserResponseAsync(user, accessTokenResult.Data, refreshToken);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<UserResponse>> GetByIdAsync(Guid id)
        {
            _logger.LogInformation("Fetching user by ID: {Id}", id);
            var user = await _userManager.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
            {
                _logger.LogInformation("User not found for ID: {Id}", id);
                return ApiResult<UserResponse>.Failure("User not found");
            }

            var userResponse = await MapUserToUserResponseAsync(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync()
        {
            var userId = _currentUserService.GetUserId();
            var user = await _userManager.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id.ToString() == userId);
            if (user == null)
            {
                _logger.LogInformation("Current user not found for ID: {Id}", userId);
                return ApiResult<CurrentUserResponse>.Failure("User not found");
            }

            var tokenResult = await _tokenServices.GenerateToken(user);
            var userResponse = MapUserToCurrentUserResponse(user, tokenResult.IsSuccess ? tokenResult.Data : string.Empty);
            return ApiResult<CurrentUserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshTokenAsync(RefreshTokenRequest request)
        {
            // Lấy user hiện tại từ current user service
            var userId = _currentUserService.GetUserId();
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogError("Current user ID not found for revoking refresh token");
                return ApiResult<RevokeRefreshTokenResponse>.Failure("User not found");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogInformation("User not found for revoking refresh token");
                return ApiResult<RevokeRefreshTokenResponse>.Failure("User not found");
            }

            // Lấy refresh token đã lưu (plain text)
            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            if (string.IsNullOrEmpty(storedRefreshToken))
            {
                _logger.LogInformation("No refresh token found for user: {Email}", user.Email);
                return ApiResult<RevokeRefreshTokenResponse>.Failure("Refresh token not found");
            }

            if (storedRefreshToken != request.RefreshToken)
            {
                _logger.LogInformation("Refresh token does not match for user: {Email}", user.Email);
                return ApiResult<RevokeRefreshTokenResponse>.Failure("Invalid refresh token");
            }

            // Gọi RemoveAuthenticationTokenAsync để revoke token
            var removeResult = await _userManager.RemoveAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            if (!removeResult.Succeeded)
            {
                _logger.LogError("Failed to revoke refresh token: {Errors}",
                    string.Join(", ", removeResult.Errors.Select(e => e.Description)));
                return ApiResult<RevokeRefreshTokenResponse>.Failure(string.Join(", ", removeResult.Errors.Select(e => e.Description)));
            }

            _logger.LogInformation("Refresh token revoked successfully for user: {Email}", user.Email);
            return ApiResult<RevokeRefreshTokenResponse>.Success(new RevokeRefreshTokenResponse { Message = "Refresh token revoked successfully" });
        }

        public async Task<ApiResult<UserResponse>> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found for ID: {Id}", id);
                return ApiResult<UserResponse>.Failure("User not found");
            }

            // Cập nhật các trường thông tin khác
            UpdateUserFields(user, request);
            user.UpdateAt = DateTime.UtcNow;

            // Nếu request có chứa thông tin Role và người gọi là Admin, cập nhật role
            if (request.Roles != null && request.Roles.Any())
            {
                if (_currentUserService.IsAdmin())
                {
                    var currentRoles = await _userManager.GetRolesAsync(user);
                    if (currentRoles.Any())
                    {
                        var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                        if (!removeResult.Succeeded)
                        {
                            _logger.LogWarning("Failed to remove existing roles for user {Id}: {Errors}",
                                id, string.Join(", ", removeResult.Errors.Select(e => e.Description)));
                            return ApiResult<UserResponse>.Failure(string.Join(", ", removeResult.Errors.Select(e => e.Description)));
                        }
                    }

                    var addResult = await _userManager.AddToRolesAsync(user, request.Roles);
                    if (!addResult.Succeeded)
                    {
                        _logger.LogWarning("Failed to add roles for user {Id}: {Errors}",
                            id, string.Join(", ", addResult.Errors.Select(e => e.Description)));
                        return ApiResult<UserResponse>.Failure(string.Join(", ", addResult.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    _logger.LogInformation("User update skipped role modification because caller is not admin");
                }
            }

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                _logger.LogWarning("Update failed for user {Id}: {Errors}", id,
                    string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                return ApiResult<UserResponse>.Failure(string.Join(", ", updateResult.Errors.Select(e => e.Description)));
            }

            var userResponse = await MapUserToUserResponseAsync(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<UserResponse>> UpdateCurrentUserAsync(UpdateUserRequest request)
        {
            var userId = _currentUserService.GetUserId();
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogInformation("Current user ID not found");
                return ApiResult<UserResponse>.Failure("Current user not found");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogInformation("User not found for ID: {Id}", userId);
                return ApiResult<UserResponse>.Failure("User not found");
            }

            UpdateUserFields(user, request);
            user.UpdateAt = DateTime.UtcNow;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                _logger.LogWarning("Update failed for current user {Id}: {Errors}", userId,
                    string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                return ApiResult<UserResponse>.Failure(string.Join(", ", updateResult.Errors.Select(e => e.Description)));
            }

            var userResponse = await MapUserToUserResponseAsync(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("Refreshing token");

            var userId = _currentUserService.GetUserId();
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogError("Current user ID not found");
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("User not found for refresh token");
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");
            }

            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            if (string.IsNullOrEmpty(storedRefreshToken))
            {
                _logger.LogError("No refresh token stored for user: {Email}", user.Email);
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");
            }

            if (storedRefreshToken != request.RefreshToken)
            {
                _logger.LogError("Refresh token does not match for user: {Email}", user.Email);
                return ApiResult<CurrentUserResponse>.Failure("Invalid refresh token");
            }

            var newAccessToken = await _tokenServices.GenerateToken(user);
            var userResponse = MapUserToCurrentUserResponse(user, newAccessToken.Data);
            _logger.LogInformation("Token refreshed successfully for user: {Email}", user.Email);
            return ApiResult<CurrentUserResponse>.Success(userResponse);
        }

        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found for deletion: {Id}", id);
                return;
            }

            await _userManager.DeleteAsync(user);
            _logger.LogInformation("User deleted: {Id}", id);
        }
        //Delete multiple users
        public async Task DeleteUsersAsync(List<Guid> ids)
        {
            _logger.LogInformation("Starting bulk deletion for users: {Ids}", string.Join(", ", ids));

            using (var transaction = await _unitOfWork.BeginTransactionAsync())
            {
                try
                {
                    foreach (var id in ids)
                    {
                        var user = await _userManager.FindByIdAsync(id.ToString());
                        if (user == null)
                        {
                            _logger.LogWarning("User not found for deletion: {Id}", id);
                            // Nếu một user không tồn tại thì ném exception để rollback toàn bộ transaction
                            throw new Exception($"User not found: {id}");
                        }

                        var result = await _userManager.DeleteAsync(user);
                        if (!result.Succeeded)
                        {
                            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                            _logger.LogWarning("Failed to delete user {Id}: {Errors}", id, errors);
                            throw new Exception($"Deletion failed for user: {id} - Errors: {errors}");
                        }

                        _logger.LogInformation("User deleted successfully: {Id}", id);
                    }
                    await transaction.CommitAsync();
                    _logger.LogInformation("Bulk deletion committed successfully for users: {Ids}", string.Join(", ", ids));
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError(ex, "Bulk deletion failed for users: {Ids}", string.Join(", ", ids));
                    throw; // ném lại exception để caller có thể biết có lỗi xảy ra
                }
            }
        }

        public async Task<UserResponse> CreateOrUpdateGoogleUserAsync(GoogleUserInfo googleUserInfo)
        {
            var user = await _userManager.FindByEmailAsync(googleUserInfo.Email);
            bool isNewUser = user == null;

            if (isNewUser)
            {
                user = new User
                {
                    UserName = googleUserInfo.Email,
                    Email = googleUserInfo.Email,
                    FirstName = googleUserInfo.FirstName,
                    LastName = googleUserInfo.LastName,
                    CreateAt = DateTime.UtcNow,
                    UpdateAt = DateTime.UtcNow
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    _logger.LogError("Google user creation failed: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                    throw new Exception("User creation failed");
                }

                var roleResult = await _userManager.AddToRoleAsync(user, "USER");
                if (!roleResult.Succeeded)
                {
                    _logger.LogError("Role assignment failed for Google user: {Errors}", string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                    throw new Exception("Assign role failed");
                }
            }
            else
            {
                bool hasChange = false;
                if (user.FirstName != googleUserInfo.FirstName)
                {
                    user.FirstName = googleUserInfo.FirstName;
                    hasChange = true;
                }
                if (user.LastName != googleUserInfo.LastName)
                {
                    user.LastName = googleUserInfo.LastName;
                    hasChange = true;
                }

                if (hasChange)
                {
                    user.UpdateAt = DateTime.UtcNow;
                    var updateResult = await _userManager.UpdateAsync(user);
                    if (!updateResult.Succeeded)
                    {
                        _logger.LogError("Google user update failed: {Errors}", string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                        throw new Exception("User update failed");
                    }
                }

                if (!await _userManager.IsInRoleAsync(user, "USER"))
                {
                    var roleResult = await _userManager.AddToRoleAsync(user, "USER");
                    if (!roleResult.Succeeded)
                    {
                        _logger.LogError("Role assignment failed for existing Google user: {Errors}", string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                        throw new Exception("Assign role failed");
                    }
                }
            }

            var tokenResult = await _tokenServices.GenerateToken(user);
            var refreshToken = _tokenServices.GenerateRefreshToken();
            // Lưu refresh token vào Identity API (không thêm expiry) – dùng plain text
            var setTokenResult = await _userManager.SetAuthenticationTokenAsync(
                user,
                "MyApp",
                "RefreshToken",
                refreshToken
            );
            if (!setTokenResult.Succeeded)
            {
                _logger.LogWarning("Failed to set refresh token for Google user: {Errors}", string.Join(", ", setTokenResult.Errors.Select(e => e.Description)));
                throw new Exception("Setting refresh token failed");
            }

            return await MapUserToUserResponseAsync(user, tokenResult.IsSuccess ? tokenResult.Data : null, refreshToken).ConfigureAwait(false);
        }

        public async Task<ApiResult<PagedList<UserDetailsDTO>>> GetUsersAsync(int pageNumber, int pageSize)
        {
            var pagedUsers = await _unitOfWork.UserRepository.GetUserDetailsAsync(pageNumber, pageSize);
            return ApiResult<PagedList<UserDetailsDTO>>.Success(pagedUsers);
        }

        public async Task<ApiResult<string>> ChangePasswordAsync(ChangePasswordRequest request)
        {
            var userId = _currentUserService.GetUserId();
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogInformation("Current user ID not found for password change");
                return ApiResult<string>.Failure("User not found");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogInformation("User not found for password change: {Id}", userId);
                return ApiResult<string>.Failure("User not found");
            }

            var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Password change failed for user {Id}: {Errors}", userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResult<string>.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded)
            {
                _logger.LogWarning("Security stamp update failed after password change for user {Id}", userId);
                return ApiResult<string>.Failure("Password changed but failed to update security stamp");
            }

            _logger.LogInformation("Password changed successfully for user: {Id}", userId);
            return ApiResult<string>.Success("Password changed successfully");
        }

        // Helpers
        private string GenerateUserName(string firstName, string lastName)
        {
            var baseUsername = $"{firstName.Replace(" ", "")}{lastName.Replace(" ", "")}".ToLower();
            return $"{baseUsername}{Guid.NewGuid().ToString("N").Substring(0, 8)}"; // Đảm bảo duy nhất
        }

        private async Task<UserResponse> MapUserToUserResponseAsync(User user, string? accessToken = null, string? refreshToken = null)
        {
            // Lấy danh sách role của user từ UserManager
            var roles = await _userManager.GetRolesAsync(user);
            return new UserResponse
            {
                Id = user.Id,
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender ?? string.Empty,
                PhoneNumbers = user.PhoneNumber ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Roles = roles.ToList()
            };
        }

        private CurrentUserResponse MapUserToCurrentUserResponse(User user, string? accessToken = null)
        {
            return new CurrentUserResponse
            {
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender ?? string.Empty,
                PhoneNumbers = user.PhoneNumber ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken
            };
        }

        private void UpdateUserFields(User user, UpdateUserRequest request)
        {
            if (!string.IsNullOrEmpty(request.FirstName)) user.FirstName = request.FirstName;
            if (!string.IsNullOrEmpty(request.LastName)) user.LastName = request.LastName;
            if (!string.IsNullOrEmpty(request.Email))
            {
                if (new EmailAddressAttribute().IsValid(request.Email))
                    user.Email = request.Email;
                else
                    throw new ArgumentException("Email format is not valid.");
            }
            if (!string.IsNullOrEmpty(request.Gender.ToString())) user.Gender = request.Gender.ToString();
            if (!string.IsNullOrEmpty(request.PhoneNumbers)) user.PhoneNumber = request.PhoneNumbers;

        }

        public async Task<ApiResult<UserResponse>> LockUserAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found for locking: {Id}", id);
                return ApiResult<UserResponse>.Failure("User not found");
            }

            // Kích hoạt tính năng lockout cho user nếu chưa được bật
            if (!await _userManager.GetLockoutEnabledAsync(user))
            {
                await _userManager.SetLockoutEnabledAsync(user, true);
            }

            // Đặt LockoutEnd time đến thời điểm tối đa (nghĩa là khóa vĩnh viễn)
            var result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to lock user {Id}: {Errors}",
                    id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResult<UserResponse>.Failure("Failed to lock user");
            }

            await _userManager.UpdateAsync(user);
            _logger.LogInformation("User locked indefinitely: {Id}", id);
            var userResponse = await MapUserToUserResponseAsync(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<UserResponse>> UnlockUserAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found for unlocking: {Id}", id);
                return ApiResult<UserResponse>.Failure("User not found");
            }

            // Đặt LockoutEnd về thời điểm hiện tại (hoặc null) để mở khóa
            var result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to unlock user {Id}: {Errors}",
                    id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return ApiResult<UserResponse>.Failure("Failed to unlock user");
            }

            await _userManager.UpdateAsync(user);
            _logger.LogInformation("User unlocked: {Id}", id);
            var userResponse = await MapUserToUserResponseAsync(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

    }
}
