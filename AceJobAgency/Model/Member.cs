using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Model
{
    public class Member
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [StringLength(10)]
        public string Gender { get; set; } = string.Empty;

        [Required]
        public string NRIC { get; set; } = string.Empty; // Encrypted

        [Required]
        [EmailAddress]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string? ResumePath { get; set; } // Path to uploaded file

        public string? ResumeFileName { get; set; }

        [Required]
        public string WhoAmI { get; set; } = string.Empty; // Allow all special chars

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastLogin { get; set; }

        public DateTime? LastPasswordChange { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;

        public DateTime? LockoutEnd { get; set; }

        public bool IsLocked { get; set; } = false;

        public string? SessionId { get; set; }

        public bool TwoFactorEnabled { get; set; } = false;

        public string? TwoFactorSecret { get; set; }

        // Navigation property
        public ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();
        public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    }
}
