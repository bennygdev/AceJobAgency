using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AppSec_Assignment2.Model;
using AppSec_Assignment2.ViewModels;
using AppSec_Assignment2.Services;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web;

namespace AppSec_Assignment2.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly IWebHostEnvironment _environment;
        private readonly IConfiguration _configuration;
        private readonly ILogger<RegisterModel> _logger;

        public RegisterModel(
            AuthDbContext context,
            IEncryptionService encryptionService,
            IReCaptchaService reCaptchaService,
            IWebHostEnvironment environment,
            IConfiguration configuration,
            ILogger<RegisterModel> logger)
        {
            _context = context;
            _encryptionService = encryptionService;
            _reCaptchaService = reCaptchaService;
            _environment = environment;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public RegisterViewModel Input { get; set; } = new();

        public string? ReCaptchaSiteKey { get; private set; }

        public void OnGet()
        {
            ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
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

            // Server-side password complexity validation
            if (!ValidatePasswordComplexity(Input.Password, out var passwordErrors))
            {
                foreach (var error in passwordErrors)
                {
                    ModelState.AddModelError("Input.Password", error);
                }
            }

            // Validate NRIC format
            if (!Regex.IsMatch(Input.NRIC, @"^[STFGM]\d{7}[A-Z]$"))
            {
                ModelState.AddModelError("Input.NRIC", "Please enter a valid Singapore NRIC");
            }

            // Validate Date of Birth (must be at least 16 years old)
            if (!Input.DateOfBirth.HasValue)
            {
                ModelState.AddModelError("Input.DateOfBirth", "Date of birth is required");
            }
            else
            {
                var minDate = DateTime.Today.AddYears(-100);
                var maxDate = DateTime.Today.AddYears(-16);
                if (Input.DateOfBirth.Value < minDate || Input.DateOfBirth.Value > maxDate)
                {
                    ModelState.AddModelError("Input.DateOfBirth", "You must be between 16 and 100 years old to register");
                }
            }

            // Validate resume file
            if (Input.Resume != null)
            {
                var allowedExtensions = new[] { ".docx", ".pdf" };
                var extension = Path.GetExtension(Input.Resume.FileName).ToLowerInvariant();
                
                if (!allowedExtensions.Contains(extension))
                {
                    ModelState.AddModelError("Input.Resume", "Only .docx and .pdf files are allowed");
                }

                if (Input.Resume.Length > 5 * 1024 * 1024) // 5MB limit
                {
                    ModelState.AddModelError("Input.Resume", "File size must not exceed 5MB");
                }

                // Validate file signature (magic bytes)
                if (!await IsValidFileSignature(Input.Resume, extension))
                {
                    ModelState.AddModelError("Input.Resume", "Invalid file format");
                }
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Check for duplicate email
            var existingMember = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == Input.Email.ToLower());

            if (existingMember != null)
            {
                ModelState.AddModelError("Input.Email", "An account with this email address already exists");
                return Page();
            }

            // Save resume file
            string? resumePath = null;
            string? resumeFileName = null;
            if (Input.Resume != null)
            {
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                // Generate unique filename
                var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(Input.Resume.FileName)}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await Input.Resume.CopyToAsync(stream);
                }

                resumePath = $"/uploads/resumes/{uniqueFileName}";
                resumeFileName = Input.Resume.FileName;
            }

            // Create member
            var member = new Member
            {
                FirstName = HttpUtility.HtmlEncode(Input.FirstName.Trim()),
                LastName = HttpUtility.HtmlEncode(Input.LastName.Trim()),
                Gender = Input.Gender,
                NRIC = _encryptionService.Encrypt(Input.NRIC), // Encrypted
                Email = Input.Email.ToLower().Trim(),
                PasswordHash = HashPassword(Input.Password),
                DateOfBirth = Input.DateOfBirth!.Value,
                ResumePath = resumePath,
                ResumeFileName = resumeFileName,
                WhoAmI = HttpUtility.HtmlEncode(Input.WhoAmI), // Encoded to prevent XSS
                CreatedAt = DateTime.UtcNow,
                LastPasswordChange = DateTime.UtcNow
            };

            _context.Members.Add(member);
            await _context.SaveChangesAsync();

            // Add to password history
            var passwordHistory = new PasswordHistory
            {
                MemberId = member.Id,
                PasswordHash = member.PasswordHash,
                CreatedAt = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistory);
            await _context.SaveChangesAsync();

            _logger.LogInformation("New member registered: {Email}", Input.Email);

            TempData["SuccessMessage"] = "Registration successful! Please log in.";
            return RedirectToPage("/Login");
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
            // Using Argon2-like approach with PBKDF2 (built-in .NET)
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

            // Combine salt and hash
            byte[] combined = new byte[64];
            Buffer.BlockCopy(salt, 0, combined, 0, 32);
            Buffer.BlockCopy(hash, 0, combined, 32, 32);

            return Convert.ToBase64String(combined);
        }

        private async Task<bool> IsValidFileSignature(IFormFile file, string extension)
        {
            var signatures = new Dictionary<string, byte[][]>
            {
                { ".pdf", new[] { new byte[] { 0x25, 0x50, 0x44, 0x46 } } }, // %PDF
                { ".docx", new[] { new byte[] { 0x50, 0x4B, 0x03, 0x04 } } } // PK (ZIP archive)
            };

            if (!signatures.ContainsKey(extension))
                return false;

            using var reader = new BinaryReader(file.OpenReadStream());
            var headerBytes = reader.ReadBytes(signatures[extension][0].Length);

            return signatures[extension].Any(signature =>
                headerBytes.Take(signature.Length).SequenceEqual(signature));
        }
    }
}
