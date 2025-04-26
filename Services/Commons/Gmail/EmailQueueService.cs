using Microsoft.Extensions.Logging;

namespace Services.Commons.Gmail
{
    public class EmailQueueService : IEmailQueueService
    {
        private readonly EmailQueue _emailQueue;
        private readonly ILogger<EmailQueueService> _logger;

        public EmailQueueService(EmailQueue emailQueue, ILogger<EmailQueueService> logger)
        {
            _emailQueue = emailQueue;
            _logger = logger;
        }

        public Task QueueEmailAsync(string email, string subject, string message)
        {
            return QueueEmailAsync(new List<string> { email }, subject, message);
        }

        public Task QueueEmailAsync(List<string> emails, string subject, string message)
        {
            return QueueEmailAsync(emails, subject, message, EmailPriority.Normal);
        }

        private Task QueueEmailAsync(List<string> emails, string subject, string message, EmailPriority priority)
        {
            try
            {
                var request = new EmailRequest
                {
                    To = emails,
                    Subject = subject,
                    Body = message,
                    Priority = priority
                };

                _emailQueue.EnqueueEmail(request);
                _logger.LogInformation($"Email to {string.Join(", ", emails)} queued successfully with {priority} priority");
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to queue email to {string.Join(", ", emails)}");
                throw;
            }
        }

        public Task Queue2FAEmailAsync(string email, string code)
        {
            var subject = "Mã xác thực hai yếu tố (2FA)";
            var message = $@"
                <html>
                <body>
                    <h2>Mã xác thực hai yếu tố</h2>
                    <p>Mã xác thực của bạn là: <strong>{code}</strong></p>
                    <p>Mã này có hiệu lực trong 5 phút.</p>
                    <p>Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email này.</p>
                </body>
                </html>
            ";
            return QueueEmailAsync(new List<string> { email }, subject, message, EmailPriority.High);
        }

        public Task QueuePasswordResetEmailAsync(string email, string resetLink)
        {
            var subject = "Đặt lại mật khẩu";
            var message = $@"
                <html>
                <body>
                    <h2>Yêu cầu đặt lại mật khẩu</h2>
                    <p>Vui lòng nhấp vào liên kết sau để đặt lại mật khẩu của bạn:</p>
                    <p><a href='{resetLink}'>Đặt lại mật khẩu</a></p>
                    <p>Hoặc sao chép và dán URL này vào trình duyệt của bạn:</p>
                    <p>{resetLink}</p>
                    <p>Liên kết này sẽ hết hạn sau 24 giờ.</p>
                    <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
                </body>
                </html>
            ";
            return QueueEmailAsync(new List<string> { email }, subject, message, EmailPriority.High);
        }

        public Task QueuePasswordChangedEmailAsync(string email)
        {
            var subject = "Mật khẩu của bạn đã được thay đổi";
            var message = $@"
                <html>
                <body>
                    <h2>Thông báo thay đổi mật khẩu</h2>
                    <p>Mật khẩu của bạn đã được thay đổi thành công.</p>
                    <p>Nếu bạn không thực hiện hành động này, vui lòng liên hệ với chúng tôi ngay lập tức.</p>
                </body>
                </html>
            ";
            return QueueEmailAsync(new List<string> { email }, subject, message, EmailPriority.High);
        }

        public Task QueueWelcomeEmailAsync(string email)
        {
            var subject = "Chào mừng bạn đến với SmartCertifyAPI!";
            var message = $@"
                <html>
                <body>
                    <h2>Chào mừng!</h2>
                    <p>Cảm ơn bạn đã đăng ký tài khoản.</p>
                    <p>Chúng tôi rất vui được chào đón bạn!</p>
                    <p>Hãy bắt đầu khám phá các tính năng của chúng tôi ngay bây giờ.</p>
                </body>
                </html>
            ";
            return QueueEmailAsync(new List<string> { email }, subject, message, EmailPriority.Normal);
        }
    }

}
