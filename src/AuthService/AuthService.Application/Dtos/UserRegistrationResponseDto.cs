
namespace AuthService.Application.Dtos;

public class UserRegistrationResponseDto
{
    public string? UserId { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? TenantCode { get; set; }
    public List<string> AssignedRoles { get; set; } = new List<string>();
    public DateTime CreatedAt { get; set; }
    public bool IsSuccess { get; set; }
    public List<string> Errors { get; set; } = new List<string>();
}
