using System.Net;
using System.Net.Mail;

namespace AppSec_Assignment2.Services
{
    public interface IEmailService
    {
        Task SendPasswordResetEmailAsync(string email, string resetLink);
        Task Send2FACodeAsync(string email, string code);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            var subject = "Ace Job Agency - Password Reset Request";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Password Reset Request</h2>
                    <p>You have requested to reset your password for your Ace Job Agency account.</p>
                    <p>Click the link below to reset your password:</p>
                    <p><a href='{resetLink}' style='background-color: #4F46E5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
                    <p>This link will expire in 15 minutes.</p>
                    <p>If you did not request this password reset, please ignore this email.</p>
                    <br/>
                    <p>Best regards,<br/>Ace Job Agency Team</p>
                </body>
                </html>";

            await SendEmailAsync(email, subject, body);
        }

        public async Task Send2FACodeAsync(string email, string code)
        {
            var subject = "Ace Job Agency - Your 2FA Verification Code";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Two-Factor Authentication Code</h2>
                    <p>Your verification code is:</p>
                    <h1 style='color: #4F46E5; font-size: 32px; letter-spacing: 5px;'>{code}</h1>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you did not request this code, please secure your account immediately.</p>
                    <br/>
                    <p>Best regards,<br/>Ace Job Agency Team</p>
                </body>
                </html>";

            await SendEmailAsync(email, subject, body);
        }

        private async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                var smtpHost = _configuration["Email:SmtpHost"] ?? "smtp.gmail.com";
                var smtpPort = int.Parse(_configuration["Email:SmtpPort"] ?? "587");
                var smtpUser = _configuration["Email:SmtpUser"];
                var smtpPass = _configuration["Email:SmtpPass"];
                var fromEmail = _configuration["Email:FromEmail"] ?? smtpUser;

                if (string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass))
                {
                    _logger.LogWarning("Email service not configured. Email to {Email} with subject '{Subject}' was not sent.", toEmail, subject);
                    _logger.LogInformation("Email content: {Body}", body);
                    return;
                }

                using var client = new SmtpClient(smtpHost, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUser, smtpPass),
                    EnableSsl = true
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail!, "Ace Job Agency"),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toEmail);

                await client.SendMailAsync(mailMessage);
                _logger.LogInformation("Email sent successfully to {Email}", toEmail);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
                throw;
            }
        }
    }
}
