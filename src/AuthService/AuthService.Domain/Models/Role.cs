using System.ComponentModel.DataAnnotations;

namespace AuthService.Domain.Models;

public class Role
{
    public long Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; }

    [MaxLength(500)]
    public string Description { get; set; }

    public long ApplicationId { get; set; }

    public long TenantId { get; set; }

    public bool IsActive { get; set; } = true;

    public bool IsDefault { get; set; } = false; // Flag for default role

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public string CreatedBy { get; set; }

    // Navigation properties
    public virtual Application Application { get; set; }
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<RolePolicy> RolePolicies { get; set; } = new List<RolePolicy>();
}
