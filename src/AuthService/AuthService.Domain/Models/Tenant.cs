using static System.Net.Mime.MediaTypeNames;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Domain.Models;
public class Tenant
{
    public long Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; }

    [Required]
    [MaxLength(50)]
    public string Code { get; set; } // Unique identifier

    [MaxLength(500)]
    public string Description { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    // Navigation properties
    public virtual ICollection<ApplicationUser> Users { get; set; } = new List<ApplicationUser>();
    public virtual ICollection<Role> Roles { get; set; } = new List<Role>();
    public virtual ICollection<Application> Applications { get; set; } = new List<Application>();
}
