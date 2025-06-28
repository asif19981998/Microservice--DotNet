using AuthService.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        //builder.Property(e => e.FirstName).IsRequired().HasMaxLength(100);
        //builder.Property(e => e.LastName).IsRequired().HasMaxLength(100);
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

        // Relationship with Tenant
        builder.HasOne(e => e.Tenant)
                  .WithMany(t => t.Users)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
       
    }
}
