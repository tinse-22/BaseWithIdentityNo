namespace Services.Interfaces
{
    public interface IExternalAuthService
    {
        Task<ApiResult<UserResponse>> ProcessGoogleLoginAsync();
        Task<ApiResult<UserResponse>> ProcessGoogleTokenAsync(string tokenId);

    }
}
