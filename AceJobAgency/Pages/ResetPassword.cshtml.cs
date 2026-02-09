using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Model;
using AceJobAgency.ViewModels;
using AceJobAgency.Services;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AceJobAgency.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            IConfiguration configuration,
            ILogger<ResetPasswordModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public ResetPasswordViewModel Input { get; set; } = new();

        public bool TokenValid { get; set; }
        public bool ResetComplete { get; set; }

        public async Task<IActionResult> OnGetAsync(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                TokenValid = false;
                return Page();
            }

            Input.Token = token;
            Input.Email = email;

            // Validate token
            var resetToken = await _context.PasswordResetTokens
                .Include(t => t.Member)
                .FirstOrDefaultAsync(t => t.Token == token && 
                                         t.Member!.Email.ToLower() == email.ToLower() &&
                                         !t.IsUsed &&
                                         t.ExpiresAt > DateTime.UtcNow);

            TokenValid = resetToken != null;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
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
                TokenValid = true;
                return Page();
            }

            // Validate token again
            var resetToken = await _context.PasswordResetTokens
                .Include(t => t.Member)
                .FirstOrDefaultAsync(t => t.Token == Input.Token && 
                                         t.Member!.Email.ToLower() == Input.Email.ToLower() &&
                                         !t.IsUsed &&
                                         t.ExpiresAt > DateTime.UtcNow);

            if (resetToken == null)
            {
                TokenValid = false;
                ModelState.AddModelError("", "Invalid or expired reset token");
                return Page();
            }

            var member = resetToken.Member!;

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
                    TokenValid = true;
                    return Page();
                }
            }

            // Check if new password is same as current
            if (VerifyPassword(Input.NewPassword, member.PasswordHash))
            {
                ModelState.AddModelError("Input.NewPassword", "New password cannot be the same as current password");
                TokenValid = true;
                return Page();
            }

            // Update password
            var newPasswordHash = HashPassword(Input.NewPassword);
            member.PasswordHash = newPasswordHash;
            member.LastPasswordChange = DateTime.UtcNow;
            member.FailedLoginAttempts = 0;
            member.IsLocked = false;
            member.LockoutEnd = null;

            // Mark token as used
            resetToken.IsUsed = true;

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

            await _auditLogService.LogAsync(member.Id, "PASSWORD_RESET", 
                "Password reset via email link", HttpContext);

            _logger.LogInformation("Password reset completed for user {Email}", member.Email);

            ResetComplete = true;
            return Page();
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
