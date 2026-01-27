using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.Services;

namespace AppSec_Assignment2.Pages
{
    public class IndexModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            AuthDbContext context, 
            IEncryptionService encryptionService,
            ILogger<IndexModel> logger)
        {
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public Member? CurrentMember { get; private set; }
        public string? DecryptedNRIC { get; private set; }
        public bool IsAuthenticated { get; private set; }

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
                }
            }

            return Page();
        }
    }
}
