using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Model;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
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
                // Find the current session and mark as inactive
                var sessionId = HttpContext.Session.GetString("SessionId");
                if (!string.IsNullOrEmpty(sessionId))
                {
                    var userSession = await _context.UserSessions
                        .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.MemberId == memberId.Value);

                    if (userSession != null)
                    {
                        userSession.IsActive = false;
                        await _context.SaveChangesAsync();
                    }
                }

                // Log the logout action
                var auditLog = new AuditLog
                {
                    MemberId = memberId.Value,
                    Action = "Logout",
                    Details = "User logged out successfully",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = Request.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow
                };
                
                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
                
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
