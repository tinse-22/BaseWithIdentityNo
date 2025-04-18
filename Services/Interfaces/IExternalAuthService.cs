namespace Services.Interfaces
{
    public interface IExternalAuthService
    {
        Task<ApiResult<UserResponse>> ProcessGoogleLoginAsync();

    }
}
