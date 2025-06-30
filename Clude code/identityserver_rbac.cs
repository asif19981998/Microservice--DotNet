// ===== 1. Domain Models =====

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public long? TenantId { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ICollection<UserRole> UserRoles { get; set; }
    public virtual Tenant Tenant { get; set; }
}

public class Tenant
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string Code { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    public virtual ICollection<ApplicationUser> Users { get; set; }
    public virtual ICollection<Role> Roles { get; set; }
    public virtual ICollection<Application> Applications { get; set; }
}

public class Application
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string ClientId { get; set; }
    public string Description { get; set; }
    public long TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<Policy> Policies { get; set; }
    public virtual ICollection<Role> Roles { get; set; }
}

public class Policy
{
    public long Id { get; set; }
    public string Name { get; set; } // e.g., "canEditNameOfEmployee"
    public string Description { get; set; }
    public string Resource { get; set; } // e.g., "employee"
    public string Action { get; set; } // e.g., "edit_name"
    public string Category { get; set; } // e.g., "employee_management"
    public long ApplicationId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    public virtual Application Application { get; set; }
    public virtual ICollection<RolePolicy> RolePolicies { get; set; }
}

public class Role
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public long ApplicationId { get; set; }
    public long TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    public virtual Application Application { get; set; }
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; }
    public virtual ICollection<RolePolicy> RolePolicies { get; set; }
}

public class UserRole
{
    public string UserId { get; set; }
    public long RoleId { get; set; }
    public string AssignedBy { get; set; }
    public DateTime AssignedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    
    public virtual ApplicationUser User { get; set; }
    public virtual Role Role { get; set; }
    public virtual ApplicationUser AssignedByUser { get; set; }
}

public class RolePolicy
{
    public long RoleId { get; set; }
    public long PolicyId { get; set; }
    public string GrantedBy { get; set; }
    public DateTime GrantedAt { get; set; }
    
    public virtual Role Role { get; set; }
    public virtual Policy Policy { get; set; }
    public virtual ApplicationUser GrantedByUser { get; set; }
}

// ===== 2. DbContext Configuration =====

public class IdentityDbContext : IdentityDbContext<ApplicationUser>
{
    public IdentityDbContext(DbContextOptions<IdentityDbContext> options) : base(options) { }
    
    public DbSet<Tenant> Tenants { get; set; }
    public DbSet<Application> Applications { get; set; }
    public DbSet<Policy> Policies { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<RolePolicy> RolePolicies { get; set; }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // User-Role many-to-many
        builder.Entity<UserRole>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });
            
        builder.Entity<UserRole>()
            .HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId);
            
        builder.Entity<UserRole>()
            .HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId);
            
        builder.Entity<UserRole>()
            .HasOne(ur => ur.AssignedByUser)
            .WithMany()
            .HasForeignKey(ur => ur.AssignedBy)
            .OnDelete(DeleteBehavior.Restrict);
        
        // Role-Policy many-to-many
        builder.Entity<RolePolicy>()
            .HasKey(rp => new { rp.RoleId, rp.PolicyId });
            
        builder.Entity<RolePolicy>()
            .HasOne(rp => rp.Role)
            .WithMany(r => r.RolePolicies)
            .HasForeignKey(rp => rp.RoleId);
            
        builder.Entity<RolePolicy>()
            .HasOne(rp => rp.Policy)
            .WithMany(p => p.RolePolicies)
            .HasForeignKey(rp => rp.PolicyId);
            
        builder.Entity<RolePolicy>()
            .HasOne(rp => rp.GrantedByUser)
            .WithMany()
            .HasForeignKey(rp => rp.GrantedBy)
            .OnDelete(DeleteBehavior.Restrict);
        
        // Unique constraints
        builder.Entity<Role>()
            .HasIndex(r => new { r.Name, r.ApplicationId, r.TenantId })
            .IsUnique();
            
        builder.Entity<Policy>()
            .HasIndex(p => new { p.Name, p.ApplicationId })
            .IsUnique();
            
        builder.Entity<Tenant>()
            .HasIndex(t => t.Code)
            .IsUnique();
    }
}

// ===== 3. Custom Profile Service for IdentityServer =====

public class CustomProfileService : IProfileService
{
    private readonly IdentityDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMemoryCache _cache;
    
    public CustomProfileService(
        IdentityDbContext context,
        UserManager<ApplicationUser> userManager,
        IMemoryCache cache)
    {
        _context = context;
        _userManager = userManager;
        _cache = cache;
    }
    
    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        if (user == null) return;
        
        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, user.Id),
            new Claim(JwtClaimTypes.PreferredUserName, user.UserName),
            new Claim(JwtClaimTypes.Email, user.Email ?? ""),
            new Claim(JwtClaimTypes.GivenName, user.FirstName ?? ""),
            new Claim(JwtClaimTypes.FamilyName, user.LastName ?? "")
        };
        
        // Add tenant information
        if (user.TenantId.HasValue)
        {
            var tenant = await _context.Tenants
                .FirstOrDefaultAsync(t => t.Id == user.TenantId.Value);
            if (tenant != null)
            {
                claims.Add(new Claim("tenant_id", tenant.Id.ToString()));
                claims.Add(new Claim("tenant_code", tenant.Code));
            }
        }
        
        // Get user permissions with caching
        var permissions = await GetUserPermissionsAsync(user.Id);
        
        // Add roles
        var roles = permissions.GroupBy(p => p.RoleName).Select(g => g.Key).ToList();
        foreach (var role in roles)
        {
            claims.Add(new Claim(JwtClaimTypes.Role, role));
        }
        
        // Add policies as permissions
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission.PolicyName));
        }
        
        // Add application-specific roles
        var appRoles = permissions
            .GroupBy(p => p.ApplicationName)
            .ToDictionary(g => g.Key, g => g.Select(x => x.RoleName).Distinct().ToList());
            
        foreach (var appRole in appRoles)
        {
            claims.Add(new Claim($"app_roles_{appRole.Key.ToLower()}", 
                string.Join(",", appRole.Value)));
        }
        
        context.IssuedClaims = claims;
    }
    
    public async Task IsActiveAsync(IsActiveContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        context.IsActive = user?.IsActive == true;
    }
    
    private async Task<List<UserPermissionDto>> GetUserPermissionsAsync(string userId)
    {
        var cacheKey = $"user_permissions_{userId}";
        
        if (_cache.TryGetValue(cacheKey, out List<UserPermissionDto> cachedPermissions))
        {
            return cachedPermissions;
        }
        
        var permissions = await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.Role.IsActive)
            .Where(ur => ur.ExpiresAt == null || ur.ExpiresAt > DateTime.UtcNow)
            .SelectMany(ur => ur.Role.RolePolicies
                .Where(rp => rp.Policy.IsActive)
                .Select(rp => new UserPermissionDto
                {
                    PolicyName = rp.Policy.Name,
                    RoleName = ur.Role.Name,
                    ApplicationName = ur.Role.Application.Name,
                    Resource = rp.Policy.Resource,
                    Action = rp.Policy.Action
                }))
            .Distinct()
            .ToListAsync();
        
        _cache.Set(cacheKey, permissions, TimeSpan.FromMinutes(30));
        return permissions;
    }
}

public class UserPermissionDto
{
    public string PolicyName { get; set; }
    public string RoleName { get; set; }
    public string ApplicationName { get; set; }
    public string Resource { get; set; }
    public string Action { get; set; }
}

// ===== 4. Admin API Controllers =====

[ApiController]
[Route("api/admin/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class PoliciesController : ControllerBase
{
    private readonly IdentityDbContext _context;
    private readonly IMemoryCache _cache;
    
    public PoliciesController(IdentityDbContext context, IMemoryCache cache)
    {
        _context = context;
        _cache = cache;
    }
    
    [HttpGet]
    public async Task<ActionResult<PagedResult<PolicyDto>>> GetPolicies(
        [FromQuery] long applicationId,
        [FromQuery] string category = null,
        [FromQuery] string search = null,
        [FromQuery] int page = 1,
        [FromQuery] int limit = 50)
    {
        var query = _context.Policies
            .Where(p => p.ApplicationId == applicationId && p.IsActive)
            .AsQueryable();
        
        if (!string.IsNullOrEmpty(category))
            query = query.Where(p => p.Category == category);
        
        if (!string.IsNullOrEmpty(search))
            query = query.Where(p => p.Name.Contains(search) || p.Description.Contains(search));
        
        var total = await query.CountAsync();
        var policies = await query
            .OrderBy(p => p.Category)
            .ThenBy(p => p.Name)
            .Skip((page - 1) * limit)
            .Take(limit)
            .Select(p => new PolicyDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                Resource = p.Resource,
                Action = p.Action,
                Category = p.Category,
                IsActive = p.IsActive
            })
            .ToListAsync();
        
        return Ok(new PagedResult<PolicyDto>
        {
            Items = policies,
            Total = total,
            Page = page,
            TotalPages = (int)Math.Ceiling((double)total / limit)
        });
    }
    
    [HttpGet("grouped")]
    public async Task<ActionResult<Dictionary<string, List<PolicyDto>>>> GetPoliciesGrouped(
        [FromQuery] long applicationId)
    {
        var policies = await _context.Policies
            .Where(p => p.ApplicationId == applicationId && p.IsActive)
            .Select(p => new PolicyDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                Resource = p.Resource,
                Action = p.Action,
                Category = p.Category
            })
            .ToListAsync();
        
        var grouped = policies
            .GroupBy(p => p.Category ?? "Uncategorized")
            .ToDictionary(g => g.Key, g => g.OrderBy(p => p.Name).ToList());
        
        return Ok(grouped);
    }
    
    [HttpPost]
    public async Task<ActionResult<PolicyDto>> CreatePolicy([FromBody] CreatePolicyDto dto)
    {
        var policy = new Policy
        {
            Name = dto.Name,
            Description = dto.Description,
            Resource = dto.Resource,
            Action = dto.Action,
            Category = dto.Category,
            ApplicationId = dto.ApplicationId,
            CreatedAt = DateTime.UtcNow
        };
        
        _context.Policies.Add(policy);
        await _context.SaveChangesAsync();
        
        return CreatedAtAction(nameof(GetPolicies), new { id = policy.Id }, 
            new PolicyDto
            {
                Id = policy.Id,
                Name = policy.Name,
                Description = policy.Description,
                Resource = policy.Resource,
                Action = policy.Action,
                Category = policy.Category,
                IsActive = policy.IsActive
            });
    }
}

[ApiController]
[Route("api/admin/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class RolesController : ControllerBase
{
    private readonly IdentityDbContext _context;
    private readonly IMemoryCache _cache;
    
    public RolesController(IdentityDbContext context, IMemoryCache cache)
    {
        _context = context;
        _cache = cache;
    }
    
    [HttpGet("{roleId}/policies")]
    public async Task<ActionResult<RoleWithPoliciesDto>> GetRoleWithPolicies(long roleId)
    {
        var role = await _context.Roles
            .Include(r => r.RolePolicies)
                .ThenInclude(rp => rp.Policy)
            .Include(r => r.RolePolicies)
                .ThenInclude(rp => rp.GrantedByUser)
            .FirstOrDefaultAsync(r => r.Id == roleId);
        
        if (role == null)
            return NotFound();
        
        var availablePolicies = await _context.Policies
            .Where(p => p.ApplicationId == role.ApplicationId && p.IsActive)
            .Where(p => !role.RolePolicies.Any(rp => rp.PolicyId == p.Id))
            .Select(p => new PolicyDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                Category = p.Category
            })
            .ToListAsync();
        
        return Ok(new RoleWithPoliciesDto
        {
            Role = new RoleDto
            {
                Id = role.Id,
                Name = role.Name,
                Description = role.Description
            },
            AssignedPolicies = role.RolePolicies.Select(rp => new AssignedPolicyDto
            {
                Id = rp.Policy.Id,
                Name = rp.Policy.Name,
                Description = rp.Policy.Description,
                AssignedAt = rp.GrantedAt,
                AssignedBy = rp.GrantedByUser?.Email
            }).ToList(),
            AvailablePolicies = availablePolicies
        });
    }
    
    [HttpPut("{roleId}/policies")]
    public async Task<IActionResult> UpdateRolePolicies(long roleId, [FromBody] UpdateRolePoliciesDto dto)
    {
        var role = await _context.Roles.FindAsync(roleId);
        if (role == null)
            return NotFound();
        
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (dto.Action == "add")
        {
            var newPolicies = dto.PolicyIds
                .Where(id => !_context.RolePolicies.Any(rp => rp.RoleId == roleId && rp.PolicyId == id))
                .Select(policyId => new RolePolicy
                {
                    RoleId = roleId,
                    PolicyId = policyId,
                    GrantedBy = currentUserId,
                    GrantedAt = DateTime.UtcNow
                });
            
            _context.RolePolicies.AddRange(newPolicies);
        }
        else if (dto.Action == "remove")
        {
            var policiesToRemove = _context.RolePolicies
                .Where(rp => rp.RoleId == roleId && dto.PolicyIds.Contains(rp.PolicyId));
            
            _context.RolePolicies.RemoveRange(policiesToRemove);
        }
        
        await _context.SaveChangesAsync();
        
        // Clear cache for all users with this role
        var usersWithRole = await _context.UserRoles
            .Where(ur => ur.RoleId == roleId)
            .Select(ur => ur.UserId)
            .ToListAsync();
        
        foreach (var userId in usersWithRole)
        {
            _cache.Remove($"user_permissions_{userId}");
        }
        
        return Ok();
    }
    
    [HttpPost]
    public async Task<ActionResult<RoleDto>> CreateRole([FromBody] CreateRoleDto dto)
    {
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        var role = new Role
        {
            Name = dto.Name,
            Description = dto.Description,
            ApplicationId = dto.ApplicationId,
            TenantId = dto.TenantId,
            CreatedAt = DateTime.UtcNow
        };
        
        _context.Roles.Add(role);
        await _context.SaveChangesAsync();
        
        // Assign policies if provided
        if (dto.PolicyIds?.Any() == true)
        {
            var rolePolicies = dto.PolicyIds.Select(policyId => new RolePolicy
            {
                RoleId = role.Id,
                PolicyId = policyId,
                GrantedBy = currentUserId,
                GrantedAt = DateTime.UtcNow
            });
            
            _context.RolePolicies.AddRange(rolePolicies);
            await _context.SaveChangesAsync();
        }
        
        return CreatedAtAction(nameof(GetRoleWithPolicies), new { roleId = role.Id },
            new RoleDto
            {
                Id = role.Id,
                Name = role.Name,
                Description = role.Description
            });
    }
}

// ===== 5. DTOs =====

public class PagedResult<T>
{
    public List<T> Items { get; set; }
    public int Total { get; set; }
    public int Page { get; set; }
    public int TotalPages { get; set; }
}

public class PolicyDto
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public string Resource { get; set; }
    public string Action { get; set; }
    public string Category { get; set; }
    public bool IsActive { get; set; }
}

public class CreatePolicyDto
{
    public string Name { get; set; }
    public string Description { get; set; }
    public string Resource { get; set; }
    public string Action { get; set; }
    public string Category { get; set; }
    public long ApplicationId { get; set; }
}

public class RoleDto
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
}

public class CreateRoleDto
{
    public string Name { get; set; }
    public string Description { get; set; }
    public long ApplicationId { get; set; }
    public long TenantId { get; set; }
    public List<long> PolicyIds { get; set; }
}

public class RoleWithPoliciesDto
{
    public RoleDto Role { get; set; }
    public List<AssignedPolicyDto> AssignedPolicies { get; set; }
    public List<PolicyDto> AvailablePolicies { get; set; }
}

public class AssignedPolicyDto
{
    public long Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public DateTime AssignedAt { get; set; }
    public string AssignedBy { get; set; }
}

public class UpdateRolePoliciesDto
{
    public List<long> PolicyIds { get; set; }
    public string Action { get; set; } // "add" or "remove"
}

// ===== 6. Startup Configuration =====

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Database
        services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlServer(connectionString));
        
        // Identity
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<IdentityDbContext>()
            .AddDefaultTokenProviders();
        
        // IdentityServer
        services.AddIdentityServer(options =>
        {
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;
        })
        .AddInMemoryIdentityResources(Config.IdentityResources)
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryClients(Config.Clients)
        .AddAspNetIdentity<ApplicationUser>()
        .AddProfileService<CustomProfileService>()
        .AddDeveloperSigningCredential();
        
        // Authorization Policies
        services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminOnly", policy =>
                policy.RequireClaim("permission", "system_admin"));
                
            options.AddPolicy("CanEditEmployee", policy =>
                policy.RequireClaim("permission", "canEditNameOfEmployee"));
                
            options.AddPolicy("CanViewEmployeeList", policy =>
                policy.RequireClaim("permission", "canViewEmployeeList"));
        });
        
        // Custom services
        services.AddScoped<IRoleService, RoleService>();
        services.AddScoped<IPolicyService, PolicyService>();
        services.AddMemoryCache();
        
        services.AddControllers();
    }
    
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}

// ===== 7. IdentityServer Configuration =====

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "roles",
                UserClaims = new List<string> {"role"}
            },
            new IdentityResource
            {
                Name = "permissions",
                UserClaims = new List<string> {"permission"}
            }
        };
    
    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            new ApiScope("hr_api", "HR Management API"),
            new ApiScope("crm_api", "CRM API"),
            new ApiScope("admin_api", "Admin API")
        };
    
    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            // HR Application
            new Client
            {
                ClientId = "hr_app",
                ClientName = "HR Management System",
                AllowedGrantTypes = GrantTypes.Code,
                ClientSecrets = { new Secret("hr_secret".Sha256()) },
                
                RedirectUris = { "https://hr.company.com/signin-oidc" },
                PostLogoutRedirectUris = { "https://hr.company.com/signout-callback-oidc" },
                
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "roles",
                    "permissions",
                    "hr_api"
                },
                
                RequirePkce = true,
                AllowPlainTextPkce = false
            },
            
            // CRM Application
            new Client
            {
                ClientId = "crm_app",
                ClientName = "CRM System",
                AllowedGrantTypes = GrantTypes.Code,
                ClientSecrets = { new Secret("crm_secret".Sha256()) },
                
                RedirectUris = { "https://crm.company.com/signin-oidc" },
                PostLogoutRedirectUris = { "https://crm.company.com/signout-callback-oidc" },
                
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "roles",
                    "permissions",
                    "crm_api"
                },
                
                RequirePkce = true,
                AllowPlainTextPkce = false
            }
        };
}

// ===== 8. Client Application Usage =====

// In your client applications (HR, CRM, etc.)
public class EmployeeController : ControllerBase
{
    private readonly IPermissionService _permissionService;
    
    public EmployeeController(IPermissionService permissionService)
    {
        _permissionService = permissionService;
    }
    
    [HttpGet]
    [Authorize]
    public async Task<IActionResult> GetEmployees()
    {
        // Check permission using claims
        if (!User.HasClaim("permission", "canViewEmployeeList"))
        {
            return Forbid();
        }
        
        // Or use policy-based authorization
        // This would be configured in the client app's Startup.cs
        var employees = await GetEmployeeListAsync();
        return Ok(employees);
    }
    
    [HttpPut("{id}/name")]
    [Authorize(Policy = "CanEditEmployee")]
    public async Task<IActionResult> UpdateEmployeeName(int id, [FromBody] string newName)
    {
        // Permission already checked by [Authorize(Policy = "CanEditEmployee")]
        await UpdateEmployeeNameAsync(id, newName);
        return Ok();
    }
    
    // Alternative: Check permissions programmatically
    [HttpPost]
    [Authorize]
    public async Task<IActionResult> CreateEmployee([FromBody] CreateEmployeeDto dto)
    {
        if (!await _permissionService.HasPermissionAsync(User, "canCreateEmployee"))
        {
            return Forbid("You don't have permission to create employees");
        }
        
        var employee = await CreateEmployeeAsync(dto);
        return CreatedAtAction(nameof(GetEmployee), new { id = employee.Id }, employee);
    }
}

// Permission Service for client applications
public interface IPermissionService
{
    Task<bool> HasPermissionAsync(ClaimsPrincipal user, string permission);
    Task<List<string>> GetUserPermissionsAsync(ClaimsPrincipal user);
}

public class PermissionService : IPermissionService
{
    public Task<bool> HasPermissionAsync(ClaimsPrincipal user, string permission)
    {
        return Task.FromResult(user.HasClaim("permission", permission));
    }
    
    public Task<List<string>> GetUserPermissionsAsync(ClaimsPrincipal user)
    {
        var permissions = user.FindAll("permission").Select(c => c.Value).ToList();
        return Task.FromResult(permissions);
    }
}

// ===== 9. Client Application Startup Configuration =====

//