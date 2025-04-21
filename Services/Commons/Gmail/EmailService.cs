using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;

namespace Services.Commons.Gmail
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<EmailSettings> emailSettings,
                            ILogger<EmailService> logger)
        {
            _emailSettings = emailSettings.Value;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var mimeMessage = new MimeMessage();
            mimeMessage.From.Add(new MailboxAddress(_emailSettings.FromName,
                                                    _emailSettings.FromEmail));
            mimeMessage.To.Add(MailboxAddress.Parse(email));
            mimeMessage.Subject = subject;
            mimeMessage.Body = new TextPart(TextFormat.Plain) { Text = message };

            try
            {
                using var client = new SmtpClient();

                // 1) Kết nối tới SMTP server Gmail
                await client.ConnectAsync(
                    _emailSettings.SmtpServer,
                    _emailSettings.SmtpPort,
                    SecureSocketOptions.StartTls);

                // 2) Xác thực bằng App Password
                await client.AuthenticateAsync(
                    _emailSettings.SmtpUsername,
                    _emailSettings.SmtpPassword);

                // 3) Gửi email
                await client.SendAsync(mimeMessage);

                // 4) Ngắt kết nối
                await client.DisconnectAsync(true);

                _logger.LogInformation("Email sent successfully to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", email);
                throw;
            }
        }

        public async Task Send2FAEmailAsync(string email, string code)
        {
            var subject = "Mã xác thực hai yếu tố (2FA)";
            var message = $"Mã xác thực của bạn là: {code}\nMã này có hiệu lực trong 5 phút.";
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            var subject = "Đặt lại mật khẩu";
            var message = $"Vui lòng nhấp vào liên kết sau để đặt lại mật khẩu của bạn: {resetLink}\nLiên kết này sẽ hết hạn sau 24 giờ.";
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendPasswordChangedEmailAsync(string email)
        {
            var subject = "Mật khẩu của bạn đã được thay đổi";
            var message = "Mật khẩu của bạn đã được thay đổi thành công. Nếu bạn không thực hiện hành động này, vui lòng liên hệ với chúng tôi ngay lập tức.";
            await SendEmailAsync(email, subject, message);
        }

        public async Task SendWelcomeEmailAsync(string email)
        {
            var subject = "Chào mừng bạn đến với SmartCertifyAPI!";
            var message = "Cảm ơn bạn đã đăng ký tài khoản. Chúng tôi rất vui được chào đón bạn!";
            await SendEmailAsync(email, subject, message);
        }
    }
}
