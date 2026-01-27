using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.Services;

namespace AppSec_Assignment2.Pages
{
    public class TwoFactorSetupModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<TwoFactorSetupModel> _logger;

        public TwoFactorSetupModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            ILogger<TwoFactorSetupModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public bool Is2FAEnabled { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToPage("/Login");
            }

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null)
            {
                return RedirectToPage("/Login");
            }

            Is2FAEnabled = member.TwoFactorEnabled;
            return Page();
        }

        public async Task<IActionResult> OnPostEnableAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToPage("/Login");
            }

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null)
            {
                return RedirectToPage("/Login");
            }

            member.TwoFactorEnabled = true;
            await _context.SaveChangesAsync();

            await _auditLogService.LogAsync(member.Id, "2FA_ENABLED", 
                "Two-factor authentication enabled", HttpContext);

            _logger.LogInformation("2FA enabled for user {Email}", member.Email);

            TempData["SuccessMessage"] = "Two-factor authentication has been enabled successfully.";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDisableAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToPage("/Login");
            }

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null)
            {
                return RedirectToPage("/Login");
            }

            member.TwoFactorEnabled = false;
            member.TwoFactorSecret = null;
            await _context.SaveChangesAsync();

            await _auditLogService.LogAsync(member.Id, "2FA_DISABLED", 
                "Two-factor authentication disabled", HttpContext);

            _logger.LogInformation("2FA disabled for user {Email}", member.Email);

            TempData["SuccessMessage"] = "Two-factor authentication has been disabled.";
            return RedirectToPage();
        }
    }
}
