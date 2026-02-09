using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Model;
using AceJobAgency.ViewModels;
using AceJobAgency.Services;
using System.Security.Cryptography;

namespace AceJobAgency.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly IAuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(
            AuthDbContext context,
            IEmailService emailService,
            IReCaptchaService reCaptchaService,
            IAuditLogService auditLogService,
            IConfiguration configuration,
            ILogger<ForgotPasswordModel> logger)
        {
            _context = context;
            _emailService = emailService;
            _reCaptchaService = reCaptchaService;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public ForgotPasswordViewModel Input { get; set; } = new();

        public string? ReCaptchaSiteKey { get; private set; }
        public bool EmailSent { get; set; }

        public void OnGet()
        {
            ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
        }

        public async Task<IActionResult> OnPostAsync()
        {
            ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            // Verify reCAPTCHA
            if (!string.IsNullOrEmpty(Input.ReCaptchaToken))
            {
                var captchaValid = await _reCaptchaService.VerifyAsync(Input.ReCaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return Page();
                }
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Always show success message to prevent email enumeration
            EmailSent = true;

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == Input.Email.ToLower());

            if (member != null)
            {
                // Generate password reset token
                var token = GenerateSecureToken();
                
                var resetToken = new PasswordResetToken
                {
                    MemberId = member.Id,
                    Token = token,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(15),
                    CreatedAt = DateTime.UtcNow
                };

                _context.PasswordResetTokens.Add(resetToken);
                await _context.SaveChangesAsync();

                // Generate reset link
                var resetLink = Url.Page(
                    "/ResetPassword",
                    pageHandler: null,
                    values: new { token = token, email = member.Email },
                    protocol: Request.Scheme);

                // Send email
                try
                {
                    await _emailService.SendPasswordResetEmailAsync(member.Email, resetLink!);
                    await _auditLogService.LogAsync(member.Id, "PASSWORD_RESET_REQUESTED", 
                        "Password reset email sent", HttpContext);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send password reset email to {Email}", member.Email);
                }
            }

            // Add delay to prevent timing attacks
            await Task.Delay(Random.Shared.Next(500, 1500));

            return Page();
        }

        private static string GenerateSecureToken()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }
    }
}
