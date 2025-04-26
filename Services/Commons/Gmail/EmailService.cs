using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Services.Commons.Gmail
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<EmailSettings> emailSettings, ILogger<EmailService> logger)
        {
            _emailSettings = emailSettings.Value;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            await SendEmailAsync(new List<string> { email }, subject, message);
        }

        public async Task SendEmailAsync(List<string> to, string subject, string message)
        {
            if (to == null || to.Count == 0)
                throw new ArgumentException("Recipient list cannot be empty", nameof(to));
            if (string.IsNullOrEmpty(subject))
                throw new ArgumentException("Subject cannot be empty", nameof(subject));
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be empty", nameof(message));

            var email = new MimeMessage();
            email.From.Add(new MailboxAddress(_emailSettings.FromName, _emailSettings.FromEmail));

            foreach (var recipient in to)
            {
                email.To.Add(MailboxAddress.Parse(recipient));
            }

            email.Subject = subject;
            email.Body = new TextPart("html") { Text = message };

            try
            {
                using var smtp = new SmtpClient();
                await smtp.ConnectAsync(_emailSettings.SmtpServer, _emailSettings.SmtpPort, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync(_emailSettings.SmtpUsername, _emailSettings.SmtpPassword);
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);

                _logger.LogInformation($"Email sent successfully to {string.Join(", ", to)}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to send email to {string.Join(", ", to)}");
                throw;
            }
        }

        public async Task Send2FAEmailAsync(string email, string code)
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
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
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
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendPasswordChangedEmailAsync(string email)
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
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendWelcomeEmailAsync(string email)
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
            await SendEmailAsync(email, subject, message);
        }
    }
}
