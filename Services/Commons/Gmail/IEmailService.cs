namespace Services.Commons.Gmail
{
    public interface IEmailService : IEmailSender
    {
        Task Send2FAEmailAsync(string email, string code);
        Task SendPasswordResetEmailAsync(string email, string resetLink);
        Task SendPasswordChangedEmailAsync(string email);
        Task SendWelcomeEmailAsync(string email);
    }
}
