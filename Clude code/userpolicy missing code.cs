// ===== 1. Additional Entity for Direct User-Policy Assignment =====

// UserPolicy junction table for direct policy assignments
public class UserPolicy
{
    public string UserId { get; set; }
    
    public long PolicyId { get; set; }
    
    public string GrantedBy { get; set; }
    
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? ExpiresAt { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public string Reason { get; set; } // Optional: reason for direct assignment
    
    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual Policy Policy { get; set; }
    public virtual ApplicationUser GrantedByUser { get; set; }
}

// ===== 2. Update ApplicationUser Entity =====

// Add this to the existing ApplicationUser class
public class ApplicationUser : IdentityUser
{
    // ... existing properties ...
    
    // Add navigation property for direct policy assignments
    public virtual ICollection<UserPolicy> UserPolicies { get; set; } = new List<UserPolicy>();
}

// ===== 3. Update Policy Entity =====

// Add this to the existing Policy class
public class Policy
{
    // ... existing properties ...
    
    // Add navigation property for direct user assignments
    public virtual ICollection<UserPolicy> UserPolicies { get; set; } = new List<UserPolicy>();
}

// ===== 4. Update DbContext Configuration =====

// Add this to the OnModelCreating method in ApplicationDbContext
protected override void OnModelCreating(ModelBuilder builder)
{
    // ... existing configurations ...
    
    // Configure UserPolicy (Many-to-Many with additional properties)
    builder.Entity<UserPolicy>(entity =>
    {
        entity.HasKey(e => new { e.UserId, e.PolicyId });
        entity.Property(e => e.GrantedAt).HasDefaultValueSql("GETUTCDATE()");
        
        // Relationships
        entity.HasOne(e => e.User)
              .WithMany(u => u.UserPolicies)
              .HasForeignKey(e => e.UserId)
              .OnDelete(DeleteBehavior.Cascade);
              
        entity.HasOne(e => e.Policy)
              .WithMany(p => p.UserPolicies)
              .HasForeignKey(e => e.PolicyId)
              .OnDelete(DeleteBehavior.Cascade);
              
        entity.HasOne(e => e.GrantedByUser)
              .WithMany()
              .HasForeignKey(e => e.GrantedBy)
              .OnDelete(DeleteBehavior.Restrict);
    });
}

// Add DbSet to ApplicationDbContext
public DbSet<UserPolicy> UserPolicies { get; set; }

// ===== 5. DTOs for User Policy Management =====

public class AssignPolicyToUserDto
{
    [Required]
    public string UserId { get; set; }
    
    [Required]
    public long PolicyId { get; set; }
    
    public DateTime? ExpiresAt { get; set; }
    
    [MaxLength(500)]
    public string Reason { get; set; }
}

public class UserPolicyDto
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public long PolicyId { get; set; }
    public string PolicyName { get; set; }
    public string PolicyDescription { get; set; }
    public string PolicyResource { get; set; }
    public string PolicyAction { get; set; }
    public string GrantedBy { get; set; }
    public string GrantedByUsername { get; set; }
    public DateTime GrantedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsActive { get; set; }
    public string Reason { get; set; }
    public string AssignmentType { get; set; } // "Direct" or "Role-based"
}

public class UserPermissionsDto
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public List<UserPolicyDto> DirectPolicies { get; set; } = new List<UserPolicyDto>();
    public List<UserPolicyDto> RoleBasedPolicies { get; set; } = new List<UserPolicyDto>();
    public List<UserPolicyDto> AllEffectivePolicies { get; set; } = new List<UserPolicyDto>();
}

// ===== 6. User Policy Management Service =====

public interface IUserPolicyService
{
    Task<bool> AssignPolicyToUserAsync(AssignPolicyToUserDto dto, string assignedBy);
    Task<bool> RevokePolicyFromUserAsync(string userId, long policyId, string revokedBy);
    Task<UserPermissionsDto> GetUserPermissionsAsync(string userId);
    Task<List<UserPolicyDto>> GetUserDirectPoliciesAsync(string userId);
    Task<List<UserPolicyDto>> GetUserRoleBasedPoliciesAsync(string userId);
    Task<bool> UserHasPolicyAsync(string userId, string policyName, string applicationClientId);
    Task<List<string>> GetUserPolicyNamesAsync(string userId, string applicationClientId);
}

public class UserPolicyService : IUserPolicyService
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<UserPolicyService> _logger;
    
    public UserPolicyService(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<UserPolicyService> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }
    
    public async Task<bool> AssignPolicyToUserAsync(AssignPolicyToUserDto dto, string assignedBy)
    {
        try
        {
            // Check if user exists
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found", dto.UserId);
                return false;
            }
            
            // Check if policy exists and is active
            var policy = await _context.Policies
                .FirstOrDefaultAsync(p => p.Id == dto.PolicyId && p.IsActive);
            if (policy == null)
            {
                _logger.LogWarning("Policy {PolicyId} not found or inactive", dto.PolicyId);
                return false;
            }
            
            // Check if assignment already exists
            var existingAssignment = await _context.UserPolicies
                .FirstOrDefaultAsync(up => up.UserId == dto.UserId && up.PolicyId == dto.PolicyId);
            
            if (existingAssignment != null)
            {
                // Update existing assignment
                existingAssignment.IsActive = true;
                existingAssignment.GrantedBy = assignedBy;
                existingAssignment.GrantedAt = DateTime.UtcNow;
                existingAssignment.ExpiresAt = dto.ExpiresAt;
                existingAssignment.Reason = dto.Reason;
            }
            else
            {
                // Create new assignment
                var userPolicy = new UserPolicy
                {
                    UserId = dto.UserId,
                    PolicyId = dto.PolicyId,
                    GrantedBy = assignedBy,
                    GrantedAt = DateTime.UtcNow,
                    ExpiresAt = dto.ExpiresAt,
                    IsActive = true,
                    Reason = dto.Reason
                };
                
                _context.UserPolicies.Add(userPolicy);
            }
            
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Policy {PolicyName} assigned directly to user {Username} by {AssignedBy}", 
                policy.Name, user.UserName, assignedBy);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning policy {PolicyId} to user {UserId}", dto.PolicyId, dto.UserId);
            return false;
        }
    }
    
    public async Task<bool> RevokePolicyFromUserAsync(string userId, long policyId, string revokedBy)
    {
        try
        {
            var userPolicy = await _context.UserPolicies
                .FirstOrDefaultAsync(up => up.UserId == userId && up.PolicyId == policyId);
            
            if (userPolicy != null)
            {
                userPolicy.IsActive = false;
                await _context.SaveChangesAsync();
                
                _logger.LogInformation("Policy {PolicyId} revoked from user {UserId} by {RevokedBy}", 
                    policyId, userId, revokedBy);
                
                return true;
            }
            
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking policy {PolicyId} from user {UserId}", policyId, userId);
            return false;
        }
    }
    
    public async Task<UserPermissionsDto> GetUserPermissionsAsync(string userId)
    {
        var directPolicies = await GetUserDirectPoliciesAsync(userId);
        var roleBasedPolicies = await GetUserRoleBasedPoliciesAsync(userId);
        
        // Combine and deduplicate policies
        var allPolicies = new List<UserPolicyDto>();
        allPolicies.AddRange(directPolicies);
        
        // Add role-based policies that aren't already covered by direct assignments
        foreach (var rolePolicy in roleBasedPolicies)
        {
            if (!allPolicies.Any(p => p.PolicyId == rolePolicy.PolicyId))
            {
                allPolicies.Add(rolePolicy);
            }
        }
        
        var user = await _userManager.FindByIdAsync(userId);
        
        return new UserPermissionsDto
        {
            UserId = userId,
            Username = user?.UserName,
            DirectPolicies = directPolicies,
            RoleBasedPolicies = roleBasedPolicies,
            AllEffectivePolicies = allPolicies
        };
    }
    
    public async Task<List<UserPolicyDto>> GetUserDirectPoliciesAsync(string userId)
    {
        return await _context.UserPolicies
            .Include(up => up.Policy)
            .Include(up => up.GrantedByUser)
            .Where(up => up.UserId == userId && up.IsActive && 
                   (up.ExpiresAt == null || up.ExpiresAt > DateTime.UtcNow))
            .Select(up => new UserPolicyDto
            {
                UserId = up.UserId,
                Username = up.User.UserName,
                PolicyId = up.PolicyId,
                PolicyName = up.Policy.Name,
                PolicyDescription = up.Policy.Description,
                PolicyResource = up.Policy.Resource,
                PolicyAction = up.Policy.Action,
                GrantedBy = up.GrantedBy,
                GrantedByUsername = up.GrantedByUser.UserName,
                GrantedAt = up.GrantedAt,
                ExpiresAt = up.ExpiresAt,
                IsActive = up.IsActive,
                Reason = up.Reason,
                AssignmentType = "Direct"
            })
            .ToListAsync();
    }
    
    public async Task<List<UserPolicyDto>> GetUserRoleBasedPoliciesAsync(string userId)
    {
        return await _context.UserRoles
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePolicies)
                    .ThenInclude(rp => rp.Policy)
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePolicies)
                    .ThenInclude(rp => rp.GrantedByUser)
            .Where(ur => ur.UserId == userId && ur.IsActive && 
                   (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.UtcNow) &&
                   ur.Role.IsActive)
            .SelectMany(ur => ur.Role.RolePolicies.Select(rp => new UserPolicyDto
            {
                UserId = userId,
                Username = ur.User.UserName,
                PolicyId = rp.PolicyId,
                PolicyName = rp.Policy.Name,
                PolicyDescription = rp.Policy.Description,
                PolicyResource = rp.Policy.Resource,
                PolicyAction = rp.Policy.Action,
                GrantedBy = rp.GrantedBy,
                GrantedByUsername = rp.GrantedByUser.UserName,
                GrantedAt = rp.GrantedAt,
                ExpiresAt = ur.ExpiresAt, // Use role assignment expiry
                IsActive = rp.Policy.IsActive,
                Reason = $"Via role: {ur.Role.Name}",
                AssignmentType = "Role-based"
            }))
            .Distinct()
            .ToListAsync();
    }
    
    public async Task<bool> UserHasPolicyAsync(string userId, string policyName, string applicationClientId)
    {
        // Check direct policy assignment
        var hasDirectPolicy = await _context.UserPolicies
            .Include(up => up.Policy)
                .ThenInclude(p => p.Application)
            .AnyAsync(up => up.UserId == userId && 
                          up.IsActive && 
                          up.Policy.Name == policyName &&
                          up.Policy.Application.ClientId == applicationClientId &&
                          up.Policy.IsActive &&
                          (up.ExpiresAt == null || up.ExpiresAt > DateTime.UtcNow));
        
        if (hasDirectPolicy) return true;
        
        // Check role-based policy assignment
        var hasRoleBasedPolicy = await _context.UserRoles
            .Include(ur => ur.Role)
                .ThenInclude(r => r.RolePolicies)
                    .ThenInclude(rp => rp.Policy)
                        .ThenInclude(p => p.Application)
            .AnyAsync(ur => ur.UserId == userId && 
                          ur.IsActive && 
                          ur.Role.IsActive &&
                          (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.UtcNow) &&
                          ur.Role.RolePolicies.Any(rp => 
                              rp.Policy.Name == policyName &&
                              rp.Policy.Application.ClientId == applicationClientId &&
                              rp.Policy.IsActive));
        
        return hasRoleBasedPolicy;
    }
    
    public async Task<List<string>> GetUserPolicyNamesAsync(string userId, string applicationClientId)
    {
        var permissions = await GetUserPermissionsAsync(userId);
        
        return permissions.AllEffectivePolicies
            .Where(p => p.PolicyName != null)
            .Select(p => p.PolicyName)
            .Distinct()
            .ToList();
    }
}

// ===== 7. API Controller for User Policy Management =====

[ApiController]
[Route("api/[controller]")]
public class UserPolicyController : ControllerBase
{
    private readonly IUserPolicyService _userPolicyService;
    private readonly ILogger<UserPolicyController> _logger;
    
    public UserPolicyController(
        IUserPolicyService userPolicyService,
        ILogger<UserPolicyController> logger)
    {
        _userPolicyService = userPolicyService;
        _logger = logger;
    }
    
    [HttpPost("assign")]
    public async Task<ActionResult> AssignPolicyToUser([FromBody] AssignPolicyToUserDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        // Get current user ID (you'll need to implement this based on your auth setup)
        var assignedBy = GetCurrentUserId();
        
        var result = await _userPolicyService.AssignPolicyToUserAsync(dto, assignedBy);
        
        if (result)
        {
            return Ok(new { message = "Policy assigned successfully" });
        }
        
        return BadRequest(new { message = "Failed to assign policy" });
    }
    
    [HttpDelete("revoke/{userId}/{policyId}")]
    public async Task<ActionResult> RevokePolicyFromUser(string userId, long policyId)
    {
        var revokedBy = GetCurrentUserId();
        
        var result = await _userPolicyService.RevokePolicyFromUserAsync(userId, policyId, revokedBy);
        
        if (result)
        {
            return Ok(new { message = "Policy revoked successfully" });
        }
        
        return BadRequest(new { message = "Failed to revoke policy" });
    }
    
    [HttpGet("permissions/{userId}")]
    public async Task<ActionResult<UserPermissionsDto>> GetUserPermissions(string userId)
    {
        var permissions = await _userPolicyService.GetUserPermissionsAsync(userId);
        return Ok(permissions);
    }
    
    [HttpGet("direct-policies/{userId}")]
    public async Task<ActionResult<List<UserPolicyDto>>> GetUserDirectPolicies(string userId)
    {
        var policies = await _userPolicyService.GetUserDirectPoliciesAsync(userId);
        return Ok(policies);
    }
    
    [HttpGet("check-permission/{userId}/{policyName}/{applicationClientId}")]
    public async Task<ActionResult<bool>> CheckUserPermission(string userId, string policyName, string applicationClientId)
    {
        var hasPermission = await _userPolicyService.UserHasPolicyAsync(userId, policyName, applicationClientId);
        return Ok(hasPermission);
    }
    
    private string GetCurrentUserId()
    {
        // Implement based on your authentication setup
        // This could be from JWT claims, session, etc.
        return User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "system";
    }
}

// ===== 8. Registration Service Updates =====

// Update the IUserRegistrationService interface
public interface IUserRegistrationService
{
    Task<UserRegistrationResponseDto> RegisterUserAsync(UserRegistrationDto dto);
    Task<Role> CreateOrGetDefaultRoleAsync(long applicationId, long tenantId, string createdBy);
    Task<bool> AssignDefaultPoliciesAsync(string userId, long applicationId); // New method
}

// Add this method to UserRegistrationService
public async Task<bool> AssignDefaultPoliciesAsync(string userId, long applicationId)
{
    try
    {
        // Get default policies for the application (you can define these)
        var defaultPolicies = await _context.Policies
            .Where(p => p.ApplicationId == applicationId && 
                       p.IsActive && 
                       p.Category == "default") // Assuming you mark default policies
            .ToListAsync();
        
        foreach (var policy in defaultPolicies)
        {
            var userPolicy = new UserPolicy
            {
                UserId = userId,
                PolicyId = policy.Id,
                GrantedBy = "system",
                GrantedAt = DateTime.UtcNow,
                IsActive = true,
                Reason = "Default policy assigned during registration"
            };
            
            _context.UserPolicies.Add(userPolicy);
        }
        
        await _context.SaveChangesAsync();
        return true;
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error assigning default policies to user {UserId}", userId);
        return false;
    }
}

// ===== 9. Usage Examples =====

/*
1. Assign a policy directly to a user:
POST /api/userpolicy/assign
{
  "userId": "12345-67890-abcdef",
  "policyId": 15,
  "expiresAt": "2025-12-31T23:59:59Z",
  "reason": "Temporary access for project XYZ"
}

2. Check if user has a specific permission:
GET /api/userpolicy/check-permission/12345-67890-abcdef/canEditEmployee/my_app_client_id

3. Get all user permissions (direct + role-based):
GET /api/userpolicy/permissions/12345-67890-abcdef

4. Revoke a direct policy assignment:
DELETE /api/userpolicy/revoke/12345-67890-abcdef/15
*/