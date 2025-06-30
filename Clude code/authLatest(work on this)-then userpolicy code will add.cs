// ===== 1. Entity Models =====

using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

// Extended ApplicationUser
public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(100)]
    public string FirstName { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string LastName { get; set; }
    
    public long? TenantId { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public string CreatedBy { get; set; }
    
    // Navigation properties
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}

// Tenant entity for multi-tenancy
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

// Application entity (different systems using the auth service)
public class Application
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
    public virtual ICollection<Role> Roles { get; set; } = new List<Role>();
}

// Policy entity (fine-grained permissions)
public class Policy
{
    public long Id { get; set; }
    
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } // e.g., "canEditNameOfEmployee"
    
    [MaxLength(500)]
    public string Description { get; set; }
    
    [MaxLength(100)]
    public string Resource { get; set; } // e.g., "employee"
    
    [MaxLength(100)]
    public string Action { get; set; } // e.g., "edit_name"
    
    [MaxLength(100)]
    public string Category { get; set; } // e.g., "employee_management"
    
    public long ApplicationId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    // Navigation properties
    public virtual Application Application { get; set; }
    public virtual ICollection<RolePolicy> RolePolicies { get; set; } = new List<RolePolicy>();
}

// Role entity
public class Role
{
    public long Id { get; set; }
    
    [Required]
    [MaxLength(200)]
    public string Name { get; set; }
    
    [MaxLength(500)]
    public string Description { get; set; }
    
    public long ApplicationId { get; set; }
    
    public long TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public bool IsDefault { get; set; } = false; // Flag for default role
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    public string CreatedBy { get; set; }
    
    // Navigation properties
    public virtual Application Application { get; set; }
    public virtual Tenant Tenant { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<RolePolicy> RolePolicies { get; set; } = new List<RolePolicy>();
}

// UserRole junction table with additional properties
public class UserRole
{
    public string UserId { get; set; }
    
    public long RoleId { get; set; }
    
    public string AssignedBy { get; set; }
    
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? ExpiresAt { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual Role Role { get; set; }
    public virtual ApplicationUser AssignedByUser { get; set; }
}

// RolePolicy junction table
public class RolePolicy
{
    public long RoleId { get; set; }
    
    public long PolicyId { get; set; }
    
    public string GrantedBy { get; set; }
    
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    public virtual Role Role { get; set; }
    public virtual Policy Policy { get; set; }
    public virtual ApplicationUser GrantedByUser { get; set; }
}

// ===== 2. DbContext Configuration =====

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }
    
    // DbSets
    public DbSet<Tenant> Tenants { get; set; }
    public DbSet<Application> Applications { get; set; }
    public DbSet<Policy> Policies { get; set; }
    public DbSet<Role> Roles { get; set; }
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
        builder.Entity<Application>(entity =>
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
        builder.Entity<Role>(entity =>
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

// ===== 3. Registration DTOs =====

public class UserRegistrationDto
{
    [Required]
    [MaxLength(100)]
    public string FirstName { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string LastName { get; set; }
    
    [Required]
    [MaxLength(256)]
    public string Username { get; set; }
    
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string Email { get; set; }
    
    [Required]
    [MinLength(6)]
    public string Password { get; set; }
    
    [MaxLength(50)]
    public string TenantCode { get; set; } // Optional, for multi-tenant
    
    [MaxLength(100)]
    public string ClientId { get; set; } // Which application is registering the user
}

public class UserRegistrationResponseDto
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string TenantCode { get; set; }
    public List<string> AssignedRoles { get; set; } = new List<string>();
    public DateTime CreatedAt { get; set; }
    public bool IsSuccess { get; set; }
    public List<string> Errors { get; set; } = new List<string>();
}

// ===== 4. User Registration Service =====

public interface IUserRegistrationService
{
    Task<UserRegistrationResponseDto> RegisterUserAsync(UserRegistrationDto dto);
    Task<Role> CreateOrGetDefaultRoleAsync(long applicationId, long tenantId, string createdBy);
}

public class UserRegistrationService : IUserRegistrationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserRegistrationService> _logger;
    
    public UserRegistrationService(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        ILogger<UserRegistrationService> logger)
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
    }
    
    public async Task<UserRegistrationResponseDto> RegisterUserAsync(UserRegistrationDto dto)
    {
        using var transaction = await _context.Database.BeginTransactionAsync();
        
        try
        {
            // 1. Get or create tenant
            var tenant = await GetOrCreateTenantAsync(dto.TenantCode);
            
            // 2. Get application
            var application = await _context.Applications
                .FirstOrDefaultAsync(a => a.ClientId == dto.ClientId && a.IsActive);
                
            if (application == null)
            {
                return new UserRegistrationResponseDto
                {
                    IsSuccess = false,
                    Errors = new List<string> { "Invalid application client ID" }
                };
            }
            
            // 3. Create user
            var user = new ApplicationUser
            {
                UserName = dto.Username,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                TenantId = tenant.Id,
                EmailConfirmed = true, // Auto-confirm for API registration
                CreatedAt = DateTime.UtcNow
            };
            
            var result = await _userManager.CreateAsync(user, dto.Password);
            
            if (!result.Succeeded)
            {
                return new UserRegistrationResponseDto
                {
                    IsSuccess = false,
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }
            
            // 4. Create or get default role
            var defaultRole = await CreateOrGetDefaultRoleAsync(application.Id, tenant.Id, user.Id);
            
            // 5. Assign default role to user
            var userRole = new UserRole
            {
                UserId = user.Id,
                RoleId = defaultRole.Id,
                AssignedBy = user.Id, // Self-assigned during registration
                AssignedAt = DateTime.UtcNow
            };
            
            _context.UserRoles.Add(userRole);
            await _context.SaveChangesAsync();
            
            await transaction.CommitAsync();
            
            _logger.LogInformation("User {Username} registered successfully with default role {RoleName}", 
                dto.Username, defaultRole.Name);
            
            return new UserRegistrationResponseDto
            {
                UserId = user.Id,
                Username = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                TenantCode = tenant.Code,
                AssignedRoles = new List<string> { defaultRole.Name },
                CreatedAt = user.CreatedAt,
                IsSuccess = true
            };
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            _logger.LogError(ex, "Error registering user {Username}", dto.Username);
            
            return new UserRegistrationResponseDto
            {
                IsSuccess = false,
                Errors = new List<string> { "An error occurred during registration" }
            };
        }
    }
    
    public async Task<Role> CreateOrGetDefaultRoleAsync(long applicationId, long tenantId, string createdBy)
    {
        const string defaultRoleName = "User";
        
        // Try to get existing default role
        var existingRole = await _context.Roles
            .FirstOrDefaultAsync(r => r.Name == defaultRoleName && 
                                    r.ApplicationId == applicationId && 
                                    r.TenantId == tenantId && 
                                    r.IsDefault && 
                                    r.IsActive);
        
        if (existingRole != null)
        {
            return existingRole;
        }
        
        // Create new default role
        var newRole = new Role
        {
            Name = defaultRoleName,
            Description = "Default user role assigned during registration",
            ApplicationId = applicationId,
            TenantId = tenantId,
            IsDefault = true,
            IsActive = true,
            CreatedBy = createdBy,
            CreatedAt = DateTime.UtcNow
        };
        
        _context.Roles.Add(newRole);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Created default role {RoleName} for application {ApplicationId} and tenant {TenantId}", 
            defaultRoleName, applicationId, tenantId);
        
        return newRole;
    }
    
    private async Task<Tenant> GetOrCreateTenantAsync(string tenantCode)
    {
        if (string.IsNullOrWhiteSpace(tenantCode))
        {
            tenantCode = "default";
        }
        
        var tenant = await _context.Tenants
            .FirstOrDefaultAsync(t => t.Code == tenantCode && t.IsActive);
        
        if (tenant == null)
        {
            tenant = new Tenant
            {
                Name = $"Tenant {tenantCode}",
                Code = tenantCode,
                Description = "Auto-created tenant during user registration",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };
            
            _context.Tenants.Add(tenant);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Created new tenant with code {TenantCode}", tenantCode);
        }
        
        return tenant;
    }
}

// ===== 5. Registration API Controller =====

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly IUserRegistrationService _registrationService;
    private readonly ILogger<AccountController> _logger;
    
    public AccountController(
        IUserRegistrationService registrationService,
        ILogger<AccountController> logger)
    {
        _registrationService = registrationService;
        _logger = logger;
    }
    
    [HttpPost("register")]
    public async Task<ActionResult<UserRegistrationResponseDto>> Register([FromBody] UserRegistrationDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new UserRegistrationResponseDto
            {
                IsSuccess = false,
                Errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList()
            });
        }
        
        try
        {
            var result = await _registrationService.RegisterUserAsync(dto);
            
            if (result.IsSuccess)
            {
                _logger.LogInformation("User registration successful for {Username}", dto.Username);
                return Ok(result);
            }
            else
            {
                _logger.LogWarning("User registration failed for {Username}: {Errors}", 
                    dto.Username, string.Join(", ", result.Errors));
                return BadRequest(result);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during user registration for {Username}", dto.Username);
            return StatusCode(500, new UserRegistrationResponseDto
            {
                IsSuccess = false,
                Errors = new List<string> { "An unexpected error occurred during registration" }
            });
        }
    }
    
    [HttpPost("check-username")]
    public async Task<ActionResult<bool>> CheckUsernameAvailability([FromBody] string username)
    {
        var userManager = HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(username);
        return Ok(user == null);
    }
    
    [HttpPost("check-email")]
    public async Task<ActionResult<bool>> CheckEmailAvailability([FromBody] string email)
    {
        var userManager = HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return Ok(user == null);
    }
}

// ===== 6. Startup Configuration =====

public class Startup
{
    private readonly IConfiguration _configuration;
    
    public Startup(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public void ConfigureServices(IServiceCollection services)
    {
        // Database Configuration
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(_configuration.GetConnectionString("DefaultConnection"),
            b => b.MigrationsAssembly("YourProjectName")));
        
        // Identity Configuration
        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 6;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireLowercase = false;
            
            // User settings
            options.User.RequireUniqueEmail = true;
            options.User.AllowedUserNameCharacters = 
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                
            // Sign-in settings
            options.SignIn.RequireConfirmedEmail = false;
            options.SignIn.RequireConfirmedPhoneNumber = false;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();
        
        // IdentityServer Configuration
        services.AddIdentityServer(options =>
        {
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;
            
            // Customize endpoints if needed
            options.UserInteraction.LoginUrl = "/Account/Login";
            options.UserInteraction.LogoutUrl = "/Account/Logout";
        })
        .AddInMemoryIdentityResources(GetIdentityResources())
        .AddInMemoryApiScopes(GetApiScopes())
        .AddInMemoryClients(GetClients())
        .AddAspNetIdentity<ApplicationUser>()
        .AddDeveloperSigningCredential(); // Use proper certificate in production
        
        // Register Services
        services.AddScoped<IUserRegistrationService, UserRegistrationService>();
        
        // API Controllers
        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();
        
        // CORS (if needed for web clients)
        services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                builder.AllowAnyOrigin()
                       .AllowAnyHeader()
                       .AllowAnyMethod();
            });
        });
    }
    
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseCors();
        
        // IdentityServer middleware
        app.UseIdentityServer();
        
        app.UseAuthentication();
        app.UseAuthorization();
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
    
    // IdentityServer Configuration Methods
    private static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "roles",
                UserClaims = new List<string> { "role" }
            }
        };
    }
    
    private static IEnumerable<ApiScope> GetApiScopes()
    {
        return new List<ApiScope>
        {
            new ApiScope("api", "Main API")
        };
    }
    
    private static IEnumerable<Client> GetClients()
    {
        return new List<Client>
        {
            new Client
            {
                ClientId = "default_app",
                ClientName = "Default Application",
                AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                ClientSecrets = { new Secret("secret".Sha256()) },
                AllowedScopes = { "openid", "profile", "email", "api" },
                AllowOfflineAccess = true
            }
        };
    }
}

// ===== 7. Database Migration Commands =====

/*
To create and run migrations:

1. Install required packages:
   dotnet add package Microsoft.EntityFrameworkCore.SqlServer
   dotnet add package Microsoft.EntityFrameworkCore.Tools
   dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
   dotnet add package Duende.IdentityServer.AspNetIdentity

2. Create initial migration:
   dotnet ef migrations add InitialCreate

3. Update database:
   dotnet ef database update

4. Seed initial data (optional):
   Create a DbInitializer class to seed default applications, tenants, etc.
*/

// ===== 8. appsettings.json Configuration =====

/*
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityServerDb;Trusted_Connection=true;MultipleActiveResultSets=true"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
*/

// ===== 9. Usage Example =====

/*
POST /api/account/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "Password123!",
  "tenantCode": "company1",
  "clientId": "default_app"
}

Response:
{
  "userId": "12345-67890-abcdef",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "tenantCode": "company1",
  "assignedRoles": ["User"],
  "createdAt": "2025-06-21T10:30:00Z",
  "isSuccess": true,
  "errors": []
}
*/