using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Domain.Models;

public class AuthConsumerApplication
{
    public long Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; }

    [Required]
    [MaxLength(100)]
    public string ClientId { get; set; } // IdentityServer ClientId

    [MaxLength(500)]
    public string Description { get; set; }

    [MaxLength(500)]
    public string BaseUrl { get; set; }

    public long TenantId { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    // Navigation properties
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<Policy> Policies { get; set; } = new List<Policy>();
    public virtual ICollection<ApplicationRole> Roles { get; set; } = new List<ApplicationRole>();
}
