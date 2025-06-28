using AuthService.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Data.Configurations;
public class ApplicationConfiguration : IEntityTypeConfiguration<AuthConsumerApplication>
{
    public void Configure(EntityTypeBuilder<AuthConsumerApplication> builder)
    {
       
            builder.HasKey(e => e.Id);
            builder.Property(e => e.Name).IsRequired().HasMaxLength(200);
            builder.Property(e => e.ClientId).IsRequired().HasMaxLength(100);
            builder.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on ClientId
            builder.HasIndex(e => e.ClientId).IsUnique();

            // Relationship with Tenant
            builder.HasOne(e => e.Tenant)
                  .WithMany(t => t.Applications)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
        
    }
}
