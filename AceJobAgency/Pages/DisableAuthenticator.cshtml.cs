using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Model;
using AceJobAgency.Services;
using OtpNet;

namespace AceJobAgency.Pages
{
    public class DisableAuthenticatorModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<DisableAuthenticatorModel> _logger;

        public DisableAuthenticatorModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            ILogger<DisableAuthenticatorModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [BindProperty]
        public string Code { get; set; } = string.Empty;

        public async Task<IActionResult> OnGetAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToPage("/Login");

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null) return RedirectToPage("/Login");

            if (!member.TwoFactorEnabled)
            {
                return RedirectToPage("/Index");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToPage("/Login");

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null) return RedirectToPage("/Login");

            if (string.IsNullOrEmpty(member.TwoFactorSecret))
            {
                // Should not happen if enabled
                member.TwoFactorEnabled = false;
                await _context.SaveChangesAsync();
                return RedirectToPage("/Index");
            }

            var base32Bytes = Base32Encoding.ToBytes(member.TwoFactorSecret);
            var totp = new Totp(base32Bytes);

            if (totp.VerifyTotp(Code, out long timeStepMatched, new VerificationWindow(2, 2)))
            {
                member.TwoFactorEnabled = false;
                member.TwoFactorSecret = null; // Clear the secret for security
                await _context.SaveChangesAsync();
                
                // Update session
                HttpContext.Session.SetString("TwoFactorEnabled", "False");

                await _auditLogService.LogAsync(member.Id, "2FA_DISABLED", "User disabled 2FA", HttpContext);
                
                TempData["SuccessMessage"] = "Two-Factor Authentication has been disabled.";
                return RedirectToPage("/Index");
            }
            else
            {
                ModelState.AddModelError("Code", "Invalid verification code. Please try again.");
                return Page();
            }
        }
    }
}
