using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.ViewModels;
using AppSec_Assignment2.Services;
using System.Security.Cryptography;

namespace AppSec_Assignment2.Pages
{
    public class LoginModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            IReCaptchaService reCaptchaService,
            IConfiguration configuration,
            ILogger<LoginModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _reCaptchaService = reCaptchaService;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public LoginViewModel Input { get; set; } = new();

        public string? ReCaptchaSiteKey { get; private set; }
        public string? Message { get; private set; }
        public string? SuccessMessage { get; private set; }

        public void OnGet(string? message = null)
        {
            ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
            
            if (message == "session_expired")
            {
                Message = "Your session has expired. Please log in again.";
            }
            else if (message == "logged_out")
            {
                SuccessMessage = "You have been successfully logged out.";
            }
            else if (message == "password_changed")
            {
                SuccessMessage = "Your password has been changed successfully. Please log in with your new password.";
            }

            if (TempData["SuccessMessage"] != null)
            {
                SuccessMessage = TempData["SuccessMessage"]?.ToString();
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            // Verify reCAPTCHA
            if (!string.IsNullOrEmpty(Input.ReCaptchaToken))
            {
                var captchaValid = await _reCaptchaService.VerifyAsync(Input.ReCaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return Page();
                }
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == Input.Email.ToLower());

            if (member == null)
            {
                // Don't reveal that email doesn't exist
                ModelState.AddModelError("", "Invalid email or password");
                await Task.Delay(Random.Shared.Next(100, 500)); // Timing attack prevention
                return Page();
            }

            // Check if account is locked
            if (member.IsLocked && member.LockoutEnd.HasValue)
            {
                if (member.LockoutEnd > DateTime.UtcNow)
                {
                    var remainingMinutes = (int)(member.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes + 1;
                    ModelState.AddModelError("", $"Account is locked. Try again in {remainingMinutes} minute(s).");
                    await _auditLogService.LogAsync(member.Id, "LOGIN_ATTEMPT_LOCKED", 
                        "Login attempt while account is locked", HttpContext);
                    return Page();
                }
                else
                {
                    // Lockout period has expired, unlock the account
                    member.IsLocked = false;
                    member.FailedLoginAttempts = 0;
                    member.LockoutEnd = null;
                    await _context.SaveChangesAsync();
                }
            }

            // Verify password
            if (!VerifyPassword(Input.Password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;
                var maxAttempts = _configuration.GetValue<int>("Security:MaxLoginAttempts", 3);
                var lockoutDuration = _configuration.GetValue<int>("Security:LockoutDurationMinutes", 15);

                await _auditLogService.LogAsync(member.Id, "LOGIN_FAILED", 
                    $"Failed login attempt {member.FailedLoginAttempts}/{maxAttempts}", HttpContext);

                if (member.FailedLoginAttempts >= maxAttempts)
                {
                    member.IsLocked = true;
                    member.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutDuration);
                    await _context.SaveChangesAsync();

                    await _auditLogService.LogAsync(member.Id, "ACCOUNT_LOCKED", 
                        $"Account locked after {maxAttempts} failed attempts", HttpContext);

                    ModelState.AddModelError("", $"Account locked due to multiple failed login attempts. Try again in {lockoutDuration} minutes.");
                    return Page();
                }

                await _context.SaveChangesAsync();
                ModelState.AddModelError("", $"Invalid email or password. {maxAttempts - member.FailedLoginAttempts} attempt(s) remaining.");
                return Page();
            }

            // Check password age
            var maxPasswordAgeDays = _configuration.GetValue<int>("Security:MaxPasswordAgeDays", 90);
            if (member.LastPasswordChange.HasValue && 
                member.LastPasswordChange.Value.AddDays(maxPasswordAgeDays) < DateTime.UtcNow)
            {
                TempData["PasswordExpired"] = true;
                TempData["ExpiredEmail"] = member.Email;
                return RedirectToPage("/ChangePassword", new { expired = true });
            }

            // Check if 2FA is enabled
            if (member.TwoFactorEnabled)
            {
                // Store temporary data for 2FA verification
                HttpContext.Session.SetInt32("2FA_MemberId", member.Id);
                HttpContext.Session.SetString("2FA_Email", member.Email);
                HttpContext.Session.SetString("2FA_RememberMe", Input.RememberMe.ToString());
                
                return RedirectToPage("/TwoFactorAuth");
            }

            // Successful login - complete the login process
            await CompleteLoginAsync(member);

            return RedirectToPage("/Index");
        }

        public async Task CompleteLoginAsync(Member member)
        {
            // Reset failed attempts
            member.FailedLoginAttempts = 0;
            member.LastLogin = DateTime.UtcNow;

            // Generate new session ID
            var sessionId = Guid.NewGuid().ToString();
            member.SessionId = sessionId;

            await _context.SaveChangesAsync();

            // Set session
            HttpContext.Session.SetInt32("MemberId", member.Id);
            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("Email", member.Email);
            HttpContext.Session.SetString("FirstName", member.FirstName);
            HttpContext.Session.SetString("LastName", member.LastName);

            await _auditLogService.LogAsync(member.Id, "LOGIN_SUCCESS", "User logged in successfully", HttpContext);

            _logger.LogInformation("User {Email} logged in successfully", member.Email);
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
