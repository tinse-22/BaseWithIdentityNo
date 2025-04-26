namespace Services.Commons.Gmail
{
    public interface IEmailService
    {
        Task SendEmailAsync(string email, string subject, string message);
        Task SendEmailAsync(List<string> to, string subject, string message);
        Task Send2FAEmailAsync(string email, string code);
        Task SendPasswordResetEmailAsync(string email, string resetLink);
        Task SendPasswordChangedEmailAsync(string email);
        Task SendWelcomeEmailAsync(string email);
    }
}
