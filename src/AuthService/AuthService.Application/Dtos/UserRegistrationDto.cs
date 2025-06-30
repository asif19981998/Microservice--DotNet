using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.Dtos;
public class UserRegistrationDto
{
   
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string? TenantCode { get; set; } 

    [Required]
    public string? ClientId { get; set; } // Which application is registering the user
}
