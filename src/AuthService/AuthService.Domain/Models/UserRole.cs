namespace AuthService.Domain.Models;
public class UserRole
{
    public string UserId { get; set; }

    public long RoleId { get; set; }

    public string AssignedBy { get; set; }

    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }

    public bool IsActive { get; set; } = true;

    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual Role Role { get; set; }
    public virtual ApplicationUser AssignedByUser { get; set; }
}
