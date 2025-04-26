namespace Services.Commons.Gmail
{
    public interface IEmailQueueService
    {
        Task QueueEmailAsync(string email, string subject, string message);
        Task QueueEmailAsync(List<string> emails, string subject, string message);
        Task Queue2FAEmailAsync(string email, string code);
        Task QueuePasswordResetEmailAsync(string email, string resetLink);
        Task QueuePasswordChangedEmailAsync(string email);
        Task QueueWelcomeEmailAsync(string email);
    }
}
