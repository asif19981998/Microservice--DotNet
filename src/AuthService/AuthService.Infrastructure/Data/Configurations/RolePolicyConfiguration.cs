using AuthService.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Data.Configurations;

public class RolePolicyConfiguration : IEntityTypeConfiguration<RolePolicy>
{
    public void Configure(EntityTypeBuilder<RolePolicy> builder)
    {
  
            builder.HasKey(e => new { e.RoleId, e.PolicyId });
            builder.Property(e => e.GrantedAt).HasDefaultValueSql("GETUTCDATE()");

            // Relationships
            builder.HasOne(e => e.Role)
                  .WithMany(r => r.RolePolicies)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(e => e.Policy)
                  .WithMany(p => p.RolePolicies)
                  .HasForeignKey(e => e.PolicyId)
                  .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(e => e.GrantedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.GrantedBy)
                  .OnDelete(DeleteBehavior.Restrict);
     
    }
}
