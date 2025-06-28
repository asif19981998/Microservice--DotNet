using AuthService.Application.Data;
using AuthService.Domain.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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
        builder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
        base.OnModelCreating(builder);

       
    }
}
