namespace Services.Interfaces
{
    public interface IExternalAuthService
    {
        Task<ApiResult<string>> ProcessGoogleLoginAsync();

    }
}
