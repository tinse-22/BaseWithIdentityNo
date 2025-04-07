using System.Security.Cryptography;
using System.Text;
using System.Transactions;
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

        public UserService(ITokenService tokenServices, ICurrentUserService currentUserService, UserManager<User> userManager, ILogger<UserService> logger)
        {
            _tokenServices = tokenServices;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Register User");

            // Kiểm tra xem email đã tồn tại hay chưa
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogInformation("Email already exists");
                return ApiResult<UserResponse>.Failure("Email already exists");
            }

            // Tạo user mới bằng cách mapping thủ công từ request
            var newUser = new User
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                Gender = request.Gender.ToString(),
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow
            };

            // Sinh username dựa trên first name và last name (sử dụng phiên bản async)
            newUser.UserName = await GenerateUserNameAsync(request.FirstName ?? string.Empty, request.LastName ?? string.Empty);

            // Sử dụng TransactionScope để đảm bảo tính nhất quán của giao dịch
            using (var scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
            {
                var createResult = await _userManager.CreateAsync(newUser, request.Password);
                if (!createResult.Succeeded)
                {
                    _logger.LogInformation("Register failed");
                    return ApiResult<UserResponse>.Failure(string.Join(", ", createResult.Errors.Select(e => e.Description)));
                }

                var roleResult = await _userManager.AddToRoleAsync(newUser, "USER");
                if (!roleResult.Succeeded)
                {
                    _logger.LogInformation("Assign role failed");
                    return ApiResult<UserResponse>.Failure(string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                }

                scope.Complete();
            }

            _logger.LogInformation("User create successful");

            var tokenResult = await _tokenServices.GenerateToken(newUser);
            // Sử dụng helper mapping
            var userResponse = MapUserToUserResponse(newUser,
                                                     accessToken: tokenResult.IsSuccess ? tokenResult.Data : null,
                                                     refreshToken: null);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        // Helper: Mapping từ User sang UserResponse
        private UserResponse MapUserToUserResponse(User user, string? accessToken = null, string? refreshToken = null)
        {
            return new UserResponse
            {
                Id = user.Id,
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender?.ToString() ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        // Helper: Mapping từ User sang CurrentUserResponse
        private CurrentUserResponse MapUserToCurrentUserResponse(User user, string? accessToken = null)
        {
            return new CurrentUserResponse
            {
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender?.ToString() ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken
            };
        }

        // Phiên bản async của GenerateUserName để tránh gọi đồng bộ trong vòng lặp
        private async Task<string> GenerateUserNameAsync(string firstName, string lastName)
        {
            var normalizedFirstName = firstName.Replace(" ", string.Empty);
            var normalizedLastName = lastName.Replace(" ", string.Empty);
            var baseUsername = $"{normalizedFirstName}{normalizedLastName}".ToLower();
            var userName = baseUsername;
            var count = 1;
            while (await _userManager.Users.AnyAsync(u => u.UserName == userName))
            {
                userName = $"{baseUsername}{count}";
                count++;
            }
            return userName;
        }

        public async Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest request)
        {
            if (request == null)
            {
                _logger.LogInformation("Login request is null!!!");
                return ApiResult<UserResponse>.Failure("Invalid request");
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogInformation("Invalid user or password");
                return ApiResult<UserResponse>.Failure("Invalid user or password");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogInformation("Account is locked.");
                return ApiResult<UserResponse>.Failure("Your account is locked due to multiple failed login attempts.");
            }

            var checkPasswordResult = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!checkPasswordResult)
            {
                await _userManager.AccessFailedAsync(user);
                _logger.LogInformation("Invalid password");
                return ApiResult<UserResponse>.Failure("Invalid user or password");
            }

            await _userManager.ResetAccessFailedCountAsync(user);

            var accessTokenResult = await _tokenServices.GenerateToken(user);
            var refreshToken = _tokenServices.GenerateRefreshToken();

            using (var sha256 = SHA256.Create())
            {
                var hashedRefreshToken = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
                user.RefreshToken = Convert.ToBase64String(hashedRefreshToken);
            }
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                _logger.LogInformation("Login failed");
                return ApiResult<UserResponse>.Failure(string.Join(", ", updateResult.Errors.Select(e => e.Description)));
            }

            var userResponse = MapUserToUserResponse(user, accessTokenResult.Data, refreshToken);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<UserResponse>> GetByIdAsync(Guid id)
        {
            _logger.LogInformation("Get user by id");
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found");
                return ApiResult<UserResponse>.Failure("User not found");
            }
            _logger.LogInformation("User found");
            var userResponse = MapUserToUserResponse(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync()
        {
            var user = await _userManager.FindByIdAsync(_currentUserService.GetUserId() ?? string.Empty);
            if (user == null)
            {
                _logger.LogInformation("User not found");
                return ApiResult<CurrentUserResponse>.Failure("User not found");
            }
            var tokenResult = await _tokenServices.GenerateToken(user);
            string accessToken = tokenResult.IsSuccess && tokenResult.Data != null ? tokenResult.Data : string.Empty;
            var userResponse = MapUserToCurrentUserResponse(user, accessToken);
            return ApiResult<CurrentUserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest)
        {
            try
            {
                var hashedRefreshToken = ComputeSha256Hash(refreshTokenRemoveRequest.RefreshToken);
                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
                if (user == null)
                {
                    _logger.LogInformation("User not found");
                    return ApiResult<RevokeRefreshTokenResponse>.Failure("User not found");
                }
                if (user.RefreshTokenExpiryTime < DateTime.UtcNow)
                {
                    _logger.LogInformation("Refresh token expired");
                    return ApiResult<RevokeRefreshTokenResponse>.Failure("Refresh token expired");
                }

                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Revoke refresh token failed");
                    return ApiResult<RevokeRefreshTokenResponse>.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));
                }
                _logger.LogInformation("Refresh token revoked successfully");
                return ApiResult<RevokeRefreshTokenResponse>.Success(new RevokeRefreshTokenResponse { Message = "Refresh token revoked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while revoking the refresh token");
                throw;
            }
        }

        private static string ComputeSha256Hash(string token)
        {
            using var sha256 = SHA256.Create();
            var tokenBytes = Encoding.UTF8.GetBytes(token);
            var hashBytes = sha256.ComputeHash(tokenBytes);
            return Convert.ToBase64String(hashBytes);
        }

        public async Task<ApiResult<UserResponse>> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found");
                return ApiResult<UserResponse>.Failure("User not found");
            }

            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.Email = request.Email;
            user.Gender = request.Gender;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                var errors = string.Join(", ", updateResult.Errors.Select(e => e.Description));
                _logger.LogInformation("Update failed: " + errors);
                return ApiResult<UserResponse>.Failure(errors);
            }

            var userResponse = MapUserToUserResponse(user);
            return ApiResult<UserResponse>.Success(userResponse);
        }

        public async Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("RefreshToken");
            var hashedRefreshToken = ComputeSha256Hash(request.RefreshToken);
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
            if (user == null)
            {
                _logger.LogError("Invalid refresh token");
                throw new Exception("Invalid refresh token");
            }
            if (user.RefreshTokenExpiryTime < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token expired for user ID: {UserId}", user.Id);
                throw new Exception("Refresh token expired");
            }
            var newAccessToken = await _tokenServices.GenerateToken(user);
            _logger.LogInformation("Access token generated successfully");
            var currentUserResponse = MapUserToCurrentUserResponse(user, newAccessToken.Data);
            return ApiResult<CurrentUserResponse>.Success(currentUserResponse);
        }

        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogInformation("User not found");
                return;
            }
            await _userManager.DeleteAsync(user);
        }

        public async Task<UserResponse> CreateOrUpdateGoogleUserAsync(GoogleUserInfo googleUserInfo)
        {
            var user = await _userManager.FindByEmailAsync(googleUserInfo.Email);

            if (user == null)
            {
                user = new User
                {
                    UserName = googleUserInfo.Email,
                    Email = googleUserInfo.Email,
                    FirstName = googleUserInfo.FirstName,
                    LastName = googleUserInfo.LastName
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    throw new Exception("User creation failed");
                }

                var roleResult = await _userManager.AddToRoleAsync(user, "USER");
                if (!roleResult.Succeeded)
                {
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
                    var updateResult = await _userManager.UpdateAsync(user);
                    if (!updateResult.Succeeded)
                    {
                        throw new Exception("User update failed");
                    }
                }

                if (!await _userManager.IsInRoleAsync(user, "USER"))
                {
                    var roleResult = await _userManager.AddToRoleAsync(user, "USER");
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception("Assign role failed");
                    }
                }
            }

            var tokenResult = await _tokenServices.GenerateToken(user);
            string accessToken = tokenResult.IsSuccess && tokenResult.Data != null ? tokenResult.Data : string.Empty;
            string refreshToken = _tokenServices.GenerateRefreshToken();

            var userResponse = MapUserToUserResponse(user, accessToken, refreshToken);
            return userResponse;
        }
    }
}
