using System.ComponentModel.DataAnnotations;

namespace AuthService.Domain.Models;

public class Policy
{
    public long Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } // e.g., "canEditNameOfEmployee"

    [MaxLength(500)]
    public string Description { get; set; }

    [MaxLength(100)]
    public string Resource { get; set; } // e.g., "employee"

    [MaxLength(100)]
    public string Action { get; set; } // e.g., "edit_name"

    [MaxLength(100)]
    public string Category { get; set; } // e.g., "employee_management"

    public long ApplicationId { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    // Navigation properties
    public virtual Application Application { get; set; }
    public virtual ICollection<RolePolicy> RolePolicies { get; set; } = new List<RolePolicy>();
}
