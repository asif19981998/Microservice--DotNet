using AuthService.Domain.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Data;

public interface IApplicationDbContext
{
    public DbSet<Tenant> Tenants { get;}
    public DbSet<AuthConsumerApplication> Applications { get;}
    public DbSet<Policy> Policies { get; }
    public DbSet<ApplicationRole> Roles { get;  }
    public DbSet<UserRole> UserRoles { get; }
    public DbSet<RolePolicy> RolePolicies { get; }
}
