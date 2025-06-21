using AuthService.Application.Data;
using AuthService.Domain.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure;

public class ApplicationDbContext: IdentityDbContext<ApplicationUser,ApplicationRole,Guid>, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {

    }

    public DbSet<Tenant> Tenants { get; set; }
    public DbSet<AuthConsumerApplication> Applications { get; set; }
    public DbSet<Policy> Policies { get; set; }
    public DbSet<ApplicationUser> Roles { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<RolePolicy> RolePolicies { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure ApplicationUser
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.FirstName).IsRequired().HasMaxLength(100);
            entity.Property(e => e.LastName).IsRequired().HasMaxLength(100);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Relationship with Tenant
            entity.HasOne(e => e.Tenant)
                  .WithMany(t => t.Users)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure Tenant
        builder.Entity<Tenant>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.Code).IsRequired().HasMaxLength(50);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on Code
            entity.HasIndex(e => e.Code).IsUnique();
        });

        // Configure Application
        builder.Entity<AuthConsumerApplication>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.ClientId).IsRequired().HasMaxLength(100);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on ClientId
            entity.HasIndex(e => e.ClientId).IsUnique();

            // Relationship with Tenant
            entity.HasOne(e => e.Tenant)
                  .WithMany(t => t.Applications)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure Policy
        builder.Entity<Policy>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on Name + ApplicationId
            entity.HasIndex(e => new { e.Name, e.ApplicationId }).IsUnique();

            // Relationship with Application
            entity.HasOne(e => e.Application)
                  .WithMany(a => a.Policies)
                  .HasForeignKey(e => e.ApplicationId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure Role
        builder.Entity<ApplicationRole>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

            // Unique constraint on Name + ApplicationId + TenantId
            entity.HasIndex(e => new { e.Name, e.ApplicationId, e.TenantId }).IsUnique();

            // Relationships
            entity.HasOne(e => e.Application)
                  .WithMany(a => a.Roles)
                  .HasForeignKey(e => e.ApplicationId)
                  .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(e => e.Tenant)
                  .WithMany(t => t.Roles)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure UserRole (Many-to-Many with additional properties)
        builder.Entity<UserRole>(entity =>
        {
            entity.HasKey(e => new { e.UserId, e.RoleId });
            entity.Property(e => e.AssignedAt).HasDefaultValueSql("GETUTCDATE()");

            // Relationships
            entity.HasOne(e => e.User)
                  .WithMany(u => u.UserRoles)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Role)
                  .WithMany(r => r.UserRoles)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.AssignedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.AssignedBy)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure RolePolicy (Many-to-Many)
        builder.Entity<RolePolicy>(entity =>
        {
            entity.HasKey(e => new { e.RoleId, e.PolicyId });
            entity.Property(e => e.GrantedAt).HasDefaultValueSql("GETUTCDATE()");

            // Relationships
            entity.HasOne(e => e.Role)
                  .WithMany(r => r.RolePolicies)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Policy)
                  .WithMany(p => p.RolePolicies)
                  .HasForeignKey(e => e.PolicyId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.GrantedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.GrantedBy)
                  .OnDelete(DeleteBehavior.Restrict);
        });
    }
}
