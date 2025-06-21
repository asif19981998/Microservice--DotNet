
namespace AuthService.Domain.Models;
public class RolePolicy
{
    public long RoleId { get; set; }

    public long PolicyId { get; set; }

    public string GrantedBy { get; set; }

    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ApplicationRole Role { get; set; }
    public virtual Policy Policy { get; set; }
    public virtual ApplicationUser GrantedByUser { get; set; }
}