using Microsoft.Extensions.Logging;

namespace Services.Commons.Gmail
{
    public class EmailQueueService : IEmailQueueService
    {
        private readonly IEmailService _emailService;
        private readonly ILogger<EmailQueueService> _logger;

        public EmailQueueService(IEmailService emailService, ILogger<EmailQueueService> logger)
        {
            _emailService = emailService;
            _logger = logger;
        }

        public async Task QueueEmailAsync(string email, string subject, string message)
        {
            // Fire-and-forget email sending; in a real app, this could push to RabbitMQ or a background worker
            _ = Task.Run(() => _emailService.SendEmailAsync(email, subject, message))
                .ContinueWith(t => _logger.LogError(t.Exception, "Failed to send email"), TaskContinuationOptions.OnlyOnFaulted);
        }
    }
}
