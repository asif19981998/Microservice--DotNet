namespace AuthService.Domain.Models;

public class UserPolicy
{
    public string UserId { get; set; }

    public long PolicyId { get; set; }

    public string GrantedBy { get; set; }

    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }

    public bool IsActive { get; set; } = true;

    public string Reason { get; set; } // Optional: reason for direct assignment

    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual Policy Policy { get; set; }
    public virtual ApplicationUser GrantedByUser { get; set; }
}
