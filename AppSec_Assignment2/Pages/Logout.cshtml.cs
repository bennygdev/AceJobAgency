using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.Services;

namespace AppSec_Assignment2.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            ILogger<LogoutModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            return await PerformLogout();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            return await PerformLogout();
        }

        private async Task<IActionResult> PerformLogout()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");

            if (memberId.HasValue)
            {
                // Log the logout action
                await _auditLogService.LogAsync(memberId.Value, "LOGOUT", "User logged out", HttpContext);

                // Clear session ID from database to invalidate session
                var member = await _context.Members.FindAsync(memberId.Value);
                if (member != null)
                {
                    member.SessionId = null;
                    await _context.SaveChangesAsync();
                }

                _logger.LogInformation("User {MemberId} logged out", memberId.Value);
            }

            // Clear all session data
            HttpContext.Session.Clear();

            // Delete session cookie
            Response.Cookies.Delete(".AceJobAgency.Session");

            return RedirectToPage("/Login", new { message = "logged_out" });
        }
    }
}
