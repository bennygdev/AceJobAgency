using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Model;
using AceJobAgency.ViewModels;
using AceJobAgency.Services;
using OtpNet;

namespace AceJobAgency.Pages
{
    public class TwoFactorAuthModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<TwoFactorAuthModel> _logger;

        public TwoFactorAuthModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            ILogger<TwoFactorAuthModel> logger)
        {
            _context = context;
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

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var memberId = HttpContext.Session.GetInt32("2FA_MemberId");
            var email = HttpContext.Session.GetString("2FA_Email");
            
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

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null)
            {
                return RedirectToPage("/Login");
            }

            // Verify TOTP Code
            if (string.IsNullOrEmpty(member.TwoFactorSecret))
            {
                // Fallback or error state
                ModelState.AddModelError("", "2FA setup is incomplete.");
                return Page();
            }

            var base32Bytes = Base32Encoding.ToBytes(member.TwoFactorSecret);
            var totp = new Totp(base32Bytes);

            if (totp.VerifyTotp(Input.Code, out long timeStepMatched, new VerificationWindow(2, 2)))
            {
                // Clear 2FA session data
                HttpContext.Session.Remove("2FA_MemberId");
                HttpContext.Session.Remove("2FA_Email");
                HttpContext.Session.Remove("2FA_RememberMe");

                // Complete login
                member.FailedLoginAttempts = 0;
                member.LastLogin = DateTime.UtcNow;

                var sessionId = Guid.NewGuid().ToString();
                member.SessionId = sessionId;

                await _context.SaveChangesAsync();
                
                // Create UserSession
                var userSession = new UserSession
                {
                    SessionId = sessionId,
                    MemberId = member.Id,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    LastActive = DateTime.UtcNow,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                    UserAgent = Request.Headers["User-Agent"].ToString()
                };
                _context.UserSessions.Add(userSession);
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
            else
            {
                ModelState.AddModelError("Input.Code", "Invalid verification code");
                await _auditLogService.LogAsync(memberId.Value, "2FA_FAILED", 
                    "Invalid 2FA code entered", HttpContext);
                return Page();
            }
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
