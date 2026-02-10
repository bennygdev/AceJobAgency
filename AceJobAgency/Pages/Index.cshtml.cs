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
        private readonly IConfiguration _configuration;

        public IndexModel(
            AuthDbContext context, 
            IEncryptionService encryptionService,
            ILogger<IndexModel> logger,
            IWebHostEnvironment environment,
            IConfiguration configuration)
        {
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
            _environment = environment;
            _configuration = configuration;
        }

        public int PasswordMinAgeMinutes { get; private set; }
        public int PasswordMaxAgeDays { get; private set; }
        public TimeSpan PasswordAge { get; private set; }
        public int MinAgeProgress { get; private set; }
        public int MaxAgeProgress { get; private set; }
        public bool CanChangePassword { get; private set; }
        public int DaysToExpiration { get; private set; }

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

                    // Password Policy Logic
                    PasswordMinAgeMinutes = _configuration.GetValue<int>("Security:MinPasswordAgeMinutes", 5);
                    PasswordMaxAgeDays = _configuration.GetValue<int>("Security:MaxPasswordAgeDays", 90);
                    
                    if (CurrentMember.LastPasswordChange.HasValue)
                    {
                        var lastChange = CurrentMember.LastPasswordChange.Value;
                        PasswordAge = DateTime.UtcNow - lastChange;
                        
                        // Min Age Calculation
                        var minAgeSpan = TimeSpan.FromMinutes(PasswordMinAgeMinutes);
                        CanChangePassword = PasswordAge >= minAgeSpan;
                        MinAgeProgress = CanChangePassword ? 100 : (int)((PasswordAge.TotalMinutes / PasswordMinAgeMinutes) * 100);
                        MinAgeProgress = Math.Clamp(MinAgeProgress, 0, 100);

                        // Max Age Calculation
                        var maxAgeSpan = TimeSpan.FromDays(PasswordMaxAgeDays);
                        DaysToExpiration = PasswordMaxAgeDays - (int)PasswordAge.TotalDays;
                        MaxAgeProgress = (int)((PasswordAge.TotalDays / PasswordMaxAgeDays) * 100);
                        MaxAgeProgress = Math.Clamp(MaxAgeProgress, 0, 100);
                    }
                    else
                    {
                        // Default if never changed (shouldn't happen for registered users, but handle safe)
                        CanChangePassword = true;
                        MinAgeProgress = 100;
                        MaxAgeProgress = 0;
                        DaysToExpiration = PasswordMaxAgeDays;
                    }
                }
            }

            return Page();
        }
    }
}
