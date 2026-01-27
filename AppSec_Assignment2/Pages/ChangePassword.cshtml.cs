using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.ViewModels;
using AppSec_Assignment2.Services;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AppSec_Assignment2.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            IConfiguration configuration,
            ILogger<ChangePasswordModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public ChangePasswordViewModel Input { get; set; } = new();

        public bool IsExpired { get; set; }
        public string? ErrorMessage { get; set; }

        public IActionResult OnGet(bool expired = false)
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            
            if (!memberId.HasValue && !expired)
            {
                return RedirectToPage("/Login");
            }

            IsExpired = expired;

            if (expired && TempData["ExpiredEmail"] != null)
            {
                TempData.Keep("ExpiredEmail");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(bool expired = false)
        {
            IsExpired = expired;

            // Server-side password complexity validation
            if (!ValidatePasswordComplexity(Input.NewPassword, out var passwordErrors))
            {
                foreach (var error in passwordErrors)
                {
                    ModelState.AddModelError("Input.NewPassword", error);
                }
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            Member? member = null;

            if (expired && TempData["ExpiredEmail"] != null)
            {
                var email = TempData["ExpiredEmail"]?.ToString();
                TempData.Keep("ExpiredEmail");
                member = await _context.Members.FirstOrDefaultAsync(m => m.Email == email);
            }
            else
            {
                var memberId = HttpContext.Session.GetInt32("MemberId");
                if (!memberId.HasValue)
                {
                    return RedirectToPage("/Login");
                }
                member = await _context.Members.FindAsync(memberId.Value);
            }

            if (member == null)
            {
                ModelState.AddModelError("", "User not found");
                return Page();
            }

            // Verify current password
            if (!VerifyPassword(Input.CurrentPassword, member.PasswordHash))
            {
                ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect");
                await _auditLogService.LogAsync(member.Id, "PASSWORD_CHANGE_FAILED", 
                    "Incorrect current password", HttpContext);
                return Page();
            }

            // Check minimum password age
            var minPasswordAgeMinutes = _configuration.GetValue<int>("Security:MinPasswordAgeMinutes", 5);
            if (member.LastPasswordChange.HasValue && 
                member.LastPasswordChange.Value.AddMinutes(minPasswordAgeMinutes) > DateTime.UtcNow)
            {
                var remainingMinutes = (int)(member.LastPasswordChange.Value.AddMinutes(minPasswordAgeMinutes) - DateTime.UtcNow).TotalMinutes + 1;
                ModelState.AddModelError("", $"You cannot change your password yet. Please wait {remainingMinutes} more minute(s).");
                return Page();
            }

            // Check password history
            var passwordHistoryCount = _configuration.GetValue<int>("Security:PasswordHistoryCount", 2);
            var passwordHistories = await _context.PasswordHistories
                .Where(ph => ph.MemberId == member.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(passwordHistoryCount)
                .ToListAsync();

            foreach (var history in passwordHistories)
            {
                if (VerifyPassword(Input.NewPassword, history.PasswordHash))
                {
                    ModelState.AddModelError("Input.NewPassword", 
                        $"Cannot reuse any of your last {passwordHistoryCount} passwords");
                    await _auditLogService.LogAsync(member.Id, "PASSWORD_CHANGE_FAILED", 
                        "Attempted to reuse previous password", HttpContext);
                    return Page();
                }
            }

            // Check if new password is same as current
            if (VerifyPassword(Input.NewPassword, member.PasswordHash))
            {
                ModelState.AddModelError("Input.NewPassword", "New password cannot be the same as current password");
                return Page();
            }

            // Update password
            var newPasswordHash = HashPassword(Input.NewPassword);
            member.PasswordHash = newPasswordHash;
            member.LastPasswordChange = DateTime.UtcNow;

            // Add to password history
            var passwordHistoryEntry = new PasswordHistory
            {
                MemberId = member.Id,
                PasswordHash = newPasswordHash,
                CreatedAt = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistoryEntry);

            // Keep only the last N passwords in history
            var oldHistories = await _context.PasswordHistories
                .Where(ph => ph.MemberId == member.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(passwordHistoryCount + 1)
                .ToListAsync();
            _context.PasswordHistories.RemoveRange(oldHistories);

            await _context.SaveChangesAsync();

            await _auditLogService.LogAsync(member.Id, "PASSWORD_CHANGED", 
                "Password changed successfully", HttpContext);

            _logger.LogInformation("Password changed for user {Email}", member.Email);

            // Clear session and redirect to login
            HttpContext.Session.Clear();
            member.SessionId = null;
            await _context.SaveChangesAsync();

            return RedirectToPage("/Login", new { message = "password_changed" });
        }

        private bool ValidatePasswordComplexity(string password, out List<string> errors)
        {
            errors = new List<string>();

            if (string.IsNullOrEmpty(password))
            {
                errors.Add("Password is required");
                return false;
            }

            if (password.Length < 12)
                errors.Add("Password must be at least 12 characters long");

            if (!Regex.IsMatch(password, @"[a-z]"))
                errors.Add("Password must contain at least one lowercase letter");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                errors.Add("Password must contain at least one uppercase letter");

            if (!Regex.IsMatch(password, @"\d"))
                errors.Add("Password must contain at least one number");

            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]"))
                errors.Add("Password must contain at least one special character");

            return errors.Count == 0;
        }

        private static string HashPassword(string password)
        {
            byte[] salt = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations: 100000,
                HashAlgorithmName.SHA256,
                outputLength: 32);

            byte[] combined = new byte[64];
            Buffer.BlockCopy(salt, 0, combined, 0, 32);
            Buffer.BlockCopy(hash, 0, combined, 32, 32);

            return Convert.ToBase64String(combined);
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            try
            {
                byte[] combined = Convert.FromBase64String(storedHash);
                
                if (combined.Length != 64)
                    return false;

                byte[] salt = new byte[32];
                byte[] storedHashBytes = new byte[32];
                Buffer.BlockCopy(combined, 0, salt, 0, 32);
                Buffer.BlockCopy(combined, 32, storedHashBytes, 0, 32);

                byte[] computedHash = Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    salt,
                    iterations: 100000,
                    HashAlgorithmName.SHA256,
                    outputLength: 32);

                return CryptographicOperations.FixedTimeEquals(computedHash, storedHashBytes);
            }
            catch
            {
                return false;
            }
        }
    }
}
