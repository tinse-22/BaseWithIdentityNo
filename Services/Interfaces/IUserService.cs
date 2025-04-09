namespace Services.Interfaces
{
    public interface IUserService
    {
        Task<ApiResult<UserResponse>> RegisterAsync(UserRegisterRequest request);
        Task<ApiResult<CurrentUserResponse>> GetCurrentUserAsync();
        Task<ApiResult<UserResponse>> GetByIdAsync(Guid id);
        Task<ApiResult<UserResponse>> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<ApiResult<RevokeRefreshTokenResponse>> RevokeRefreshTokenAsync(RefreshTokenRequest request);
        Task<ApiResult<CurrentUserResponse>> RefreshTokenAsync(RefreshTokenRequest request);
        Task<ApiResult<UserResponse>> LoginAsync(UserLoginRequest request);
        Task<UserResponse> CreateOrUpdateGoogleUserAsync(GoogleUserInfo googleUserInfo);
        Task<ApiResult<PagedList<UserDetailsDTO>>> GetUsersAsync(int pageNumber, int pageSize);
        Task<ApiResult<UserResponse>> UpdateCurrentUserAsync(UpdateUserRequest request);
        Task<ApiResult<string>> ChangePasswordAsync(ChangePasswordRequest request);
    }
}