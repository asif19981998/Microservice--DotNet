namespace AuthService.Domain.Models;
public class UserRole
{
    public Guid UserId { get; set; }

    public Guid RoleId { get; set; }

    public Guid AssignedBy { get; set; }

    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }

    public bool IsActive { get; set; } = true;

    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual ApplicationRole Role { get; set; }
    public virtual ApplicationUser AssignedByUser { get; set; }
}
