using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Model;
using AceJobAgency.Services;
using OtpNet;
using QRCoder;
using System.Drawing;
using System.Drawing.Imaging;

namespace AceJobAgency.Pages
{
    public class EnableAuthenticatorModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<EnableAuthenticatorModel> _logger;

        public EnableAuthenticatorModel(
            AuthDbContext context,
            IAuditLogService auditLogService,
            ILogger<EnableAuthenticatorModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public string QrCodeImage { get; set; } = string.Empty;
        public string SharedKey { get; set; } = string.Empty;

        [BindProperty]
        public string Code { get; set; } = string.Empty;

        public async Task<IActionResult> OnGetAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToPage("/Login");

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null) return RedirectToPage("/Login");

            if (member.TwoFactorEnabled)
            {
                return RedirectToPage("/Index");
            }

            // Generate key if not exists or if we want a fresh one for setup
            // Usually good to generate a fresh one for a new setup attempt
            var key = KeyGeneration.GenerateRandomKey(20);
            var base32String = Base32Encoding.ToString(key);
            SharedKey = base32String;
            
            // Store temporarily in session or DB? 
            // Better to store in DB but not enable yet, or store in session. 
            // Saving to DB as "Pending" or just overwriting the secret is consistent.
            member.TwoFactorSecret = base32String;
            await _context.SaveChangesAsync();

            // Generate QR Code
            var uriString = new OtpUri(OtpType.Totp, base32String, member.Email, "Ace Job Agency").ToString();
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(uriString, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);
            QrCodeImage = $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToPage("/Login");

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null) return RedirectToPage("/Login");

            var base32Bytes = Base32Encoding.ToBytes(member.TwoFactorSecret);
            var totp = new Totp(base32Bytes);

            if (totp.VerifyTotp(Code, out long timeStepMatched, new VerificationWindow(2, 2)))
            {
                member.TwoFactorEnabled = true;
                await _context.SaveChangesAsync();

                await _auditLogService.LogAsync(member.Id, "2FA_ENABLED", "User enabled 2FA with Authenticator App", HttpContext);
                
                TempData["SuccessMessage"] = "Two-Factor Authentication has been enabled. You will need to use your authenticator app to log in next time.";
                return RedirectToPage("/Index");
            }
            else
            {
                // Re-generate functionality for display if failed
                // For simplicity, we just reload the page which might regenerate the key if we are not careful.
                // But since we saved the key to DB in OnGet, we should probably read it back if we want to persist the SAME key across failures.
                // However, OnGet generates a NEW key. 
                // Fix: validation failure should maybe return Page with re-generated QR for the SAME key? 
                
                // Let's re-generate QR for the EXISTING key in DB
                var key = member.TwoFactorSecret;
                var uriString = new OtpUri(OtpType.Totp, key, member.Email, "Ace Job Agency").ToString();
                using var qrGenerator = new QRCodeGenerator();
                using var qrCodeData = qrGenerator.CreateQrCode(uriString, QRCodeGenerator.ECCLevel.Q);
                using var qrCode = new PngByteQRCode(qrCodeData);
                var qrCodeBytes = qrCode.GetGraphic(20);
                QrCodeImage = $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";
                SharedKey = key;

                ModelState.AddModelError("Code", "Invalid verification code. Please try again.");
                return Page();
            }
        }
    }
}
