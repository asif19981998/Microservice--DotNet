using AuthService.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Data.Configurations;

public class RoleConfiguration : IEntityTypeConfiguration<ApplicationRole>
{
    public void Configure(EntityTypeBuilder<ApplicationRole> builder)
    {
       
            builder.HasKey(e => e.Id);
            builder.Property(e => e.Name).IsRequired().HasMaxLength(200);
            builder.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on Name + ApplicationId + TenantId
            builder.HasIndex(e => new { e.Name, e.ApplicationId, e.TenantId }).IsUnique();

            // Relationships
            builder.HasOne(e => e.Application)
                  .WithMany(a => a.Roles)
                  .HasForeignKey(e => e.ApplicationId)
                  .OnDelete(DeleteBehavior.Restrict);

            builder.HasOne(e => e.Tenant)
                  .WithMany(t => t.Roles)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
       

    }
}
