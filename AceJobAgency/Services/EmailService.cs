using System.Net;
using System.Net.Mail;

namespace AceJobAgency.Services
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
        private readonly HttpClient _httpClient;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger, HttpClient httpClient)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClient;
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
            // Note: This method might be deprecated if we switch entirely to App 2FA, 
            // but keeping it for now in case of fallback or other notifications.
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
                var apiKey = _configuration["SMTP2GO:ApiKey"];
                var senderEmail = _configuration["SMTP2GO:SenderEmail"] ?? "support@bennygoh.me"; // Fallback or from config

                if (string.IsNullOrEmpty(apiKey))
                {
                    _logger.LogWarning("SMTP2GO API Key not configured. Email to {Email} not sent.", MaskEmail(toEmail));
                    return;
                }

                var payload = new
                {
                    api_key = apiKey,
                    to = new[] { toEmail },
                    sender = senderEmail,
                    subject = subject,
                    html_body = body
                };

                var response = await _httpClient.PostAsJsonAsync("https://api.smtp2go.com/v3/email/send", payload);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Email sent successfully to {Email} via API", MaskEmail(toEmail));
                }
                else
                {
                   var errorContent = await response.Content.ReadAsStringAsync();
                   _logger.LogError("Failed to send email to {Email}. Status: {Status}. Details: {Details}", MaskEmail(toEmail), response.StatusCode, errorContent);
                   // Throwing exception to let caller know it failed (e.g. for retries or user feedback)
                   throw new Exception($"Failed to send email: {response.StatusCode} - {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while sending email to {Email}", MaskEmail(toEmail));
                throw;
            }
        }

        private string MaskEmail(string email)
        {
            if (string.IsNullOrEmpty(email)) return "Unknown";
            var parts = email.Split('@');
            if (parts.Length != 2) return "REDACTED_EMAIL";
            
            var name = parts[0];
            var domain = parts[1];
            
            if (name.Length <= 2) return $"{name}***@{domain}";
            return $"{name[0]}***{name[^1]}@{domain}";
        }
    }
}
