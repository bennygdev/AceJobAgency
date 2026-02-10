using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Model;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class IndexModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<IndexModel> _logger;
        private readonly IWebHostEnvironment _environment;

        public IndexModel(
            AuthDbContext context, 
            IEncryptionService encryptionService,
            ILogger<IndexModel> logger,
            IWebHostEnvironment environment)
        {
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
            _environment = environment;
        }

        public async Task<IActionResult> OnGetDownloadResume()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToPage("/Login");
            }

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null || string.IsNullOrEmpty(member.ResumePath))
            {
                return NotFound();
            }

            // Path.Combine prevents directory traversal if filename is just a name
            // If ResumePath is a full legacy path (starts with /), we need to handle it or migrate data. 
            // For now, let's assume new uploads or simple filenames. 
            // If it starts with /, we strip it to handle legacy test data if any.
            var filename = Path.GetFileName(member.ResumePath); 
            var filePath = Path.Combine(_environment.ContentRootPath, "Uploads", "resumes", filename);

            if (!System.IO.File.Exists(filePath))
            {
                // Fallback for legacy files in wwwroot if they exist
                var legacyPath = Path.Combine(_environment.WebRootPath, "uploads", "resumes", filename);
                if (System.IO.File.Exists(legacyPath))
                {
                    filePath = legacyPath;
                }
                else
                {
                    return NotFound();
                }
            }

            var contentType = "application/octet-stream";
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            if (extension == ".pdf") contentType = "application/pdf";
            else if (extension == ".docx") contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

            return PhysicalFile(filePath, contentType, member.ResumeFileName ?? "resume" + extension);
        }

        public Member? CurrentMember { get; private set; }
        public string? DecryptedNRIC { get; private set; }
        public bool IsAuthenticated { get; private set; }
        
        public List<UserSession> ActiveSessions { get; private set; } = new();
        public List<AuditLog> RecentActivity { get; private set; } = new();

        public async Task<IActionResult> OnGetAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            
            if (memberId.HasValue)
            {
                IsAuthenticated = true;
                CurrentMember = await _context.Members.FindAsync(memberId.Value);
                
                if (CurrentMember != null)
                {
                    // Decrypt NRIC for display
                    DecryptedNRIC = _encryptionService.Decrypt(CurrentMember.NRIC);
                    
                    // Fetch active sessions
                    ActiveSessions = await _context.UserSessions
                        .Where(s => s.MemberId == memberId.Value && s.IsActive)
                        .OrderByDescending(s => s.LastActive)
                        .ToListAsync();
                        
                    // Fetch recent activity
                    RecentActivity = await _context.AuditLogs
                        .Where(l => l.MemberId == memberId.Value)
                        .OrderByDescending(l => l.Timestamp)
                        .Take(10)
                        .ToListAsync();
                }
            }

            return Page();
        }
    }
}
