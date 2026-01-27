using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.ViewModels;
using AppSec_Assignment2.Services;
using System.Security.Cryptography;

namespace AppSec_Assignment2.Pages
{
    public class TwoFactorAuthModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<TwoFactorAuthModel> _logger;

        private static readonly Dictionary<int, (string Code, DateTime Expiry)> _pendingCodes = new();

        public TwoFactorAuthModel(
            AuthDbContext context,
            IEmailService emailService,
            IAuditLogService auditLogService,
            ILogger<TwoFactorAuthModel> logger)
        {
            _context = context;
            _emailService = emailService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [BindProperty]
        public TwoFactorViewModel Input { get; set; } = new();

        public string? MaskedEmail { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var memberId = HttpContext.Session.GetInt32("2FA_MemberId");
            var email = HttpContext.Session.GetString("2FA_Email");

            if (!memberId.HasValue || string.IsNullOrEmpty(email))
            {
                return RedirectToPage("/Login");
            }

            Input.Email = email;
            MaskedEmail = MaskEmail(email);

            // Generate and send 2FA code
            await SendVerificationCodeAsync(memberId.Value, email);

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var memberId = HttpContext.Session.GetInt32("2FA_MemberId");
            var email = HttpContext.Session.GetString("2FA_Email");
            var rememberMe = HttpContext.Session.GetString("2FA_RememberMe") == "True";

            if (!memberId.HasValue || string.IsNullOrEmpty(email))
            {
                return RedirectToPage("/Login");
            }

            Input.Email = email;
            MaskedEmail = MaskEmail(email);

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify the code
            if (!VerifyCode(memberId.Value, Input.Code))
            {
                ModelState.AddModelError("Input.Code", "Invalid or expired verification code");
                await _auditLogService.LogAsync(memberId.Value, "2FA_FAILED", 
                    "Invalid 2FA code entered", HttpContext);
                return Page();
            }

            // Clear pending code
            _pendingCodes.Remove(memberId.Value);

            // Clear 2FA session data
            HttpContext.Session.Remove("2FA_MemberId");
            HttpContext.Session.Remove("2FA_Email");
            HttpContext.Session.Remove("2FA_RememberMe");

            // Get member and complete login
            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null)
            {
                return RedirectToPage("/Login");
            }

            // Complete login
            member.FailedLoginAttempts = 0;
            member.LastLogin = DateTime.UtcNow;

            var sessionId = Guid.NewGuid().ToString();
            member.SessionId = sessionId;

            await _context.SaveChangesAsync();

            HttpContext.Session.SetInt32("MemberId", member.Id);
            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("Email", member.Email);
            HttpContext.Session.SetString("FirstName", member.FirstName);
            HttpContext.Session.SetString("LastName", member.LastName);

            await _auditLogService.LogAsync(member.Id, "LOGIN_SUCCESS_2FA", 
                "User logged in with 2FA", HttpContext);

            _logger.LogInformation("User {Email} logged in with 2FA", member.Email);

            return RedirectToPage("/Index");
        }

        public async Task<IActionResult> OnPostResendAsync()
        {
            var memberId = HttpContext.Session.GetInt32("2FA_MemberId");
            var email = HttpContext.Session.GetString("2FA_Email");

            if (!memberId.HasValue || string.IsNullOrEmpty(email))
            {
                return RedirectToPage("/Login");
            }

            await SendVerificationCodeAsync(memberId.Value, email);

            TempData["Message"] = "A new verification code has been sent to your email.";
            return RedirectToPage();
        }

        private async Task SendVerificationCodeAsync(int memberId, string email)
        {
            // Generate 6-digit code
            var code = GenerateVerificationCode();
            var expiry = DateTime.UtcNow.AddMinutes(5);

            _pendingCodes[memberId] = (code, expiry);

            try
            {
                await _emailService.Send2FACodeAsync(email, code);
                _logger.LogInformation("2FA code sent to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send 2FA code to {Email}", email);
            }
        }

        private static string GenerateVerificationCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var num = BitConverter.ToUInt32(bytes, 0) % 1000000;
            return num.ToString("D6");
        }

        private static bool VerifyCode(int memberId, string code)
        {
            if (_pendingCodes.TryGetValue(memberId, out var stored))
            {
                if (stored.Expiry > DateTime.UtcNow && stored.Code == code)
                {
                    return true;
                }
            }
            return false;
        }

        private static string MaskEmail(string email)
        {
            var parts = email.Split('@');
            if (parts.Length != 2) return email;

            var name = parts[0];
            var domain = parts[1];

            if (name.Length <= 2)
                return $"{name}***@{domain}";

            return $"{name[0]}***{name[^1]}@{domain}";
        }
    }
}
