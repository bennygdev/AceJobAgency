using AceJobAgency.Model;

namespace AceJobAgency.Services
{
    public interface IAuditLogService
    {
        Task LogAsync(int memberId, string action, string? details = null, HttpContext? httpContext = null);
    }

    public class AuditLogService : IAuditLogService
    {
        private readonly AuthDbContext _context;

        public AuditLogService(AuthDbContext context)
        {
            _context = context;
        }

        public async Task LogAsync(int memberId, string action, string? details = null, HttpContext? httpContext = null)
        {
            var auditLog = new AuditLog
            {
                MemberId = memberId,
                Action = action,
                Details = details,
                IpAddress = httpContext?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = httpContext?.Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}
