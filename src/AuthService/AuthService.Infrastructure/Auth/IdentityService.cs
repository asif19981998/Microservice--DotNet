using AuthService.Application.Data;
using AuthService.Domain.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Auth;

public class IdentityService:IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public IdentityService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<bool> RegisterUserAsync(ApplicationUser applicationUser, string password)
    {
        var user = new ApplicationUser
        {
            Email = applicationUser.Email,
            UserName = applicationUser.UserName,
            CreatedBy = applicationUser.UserName,
            FirstName = applicationUser.FirstName ?? "Default",
            LastName = applicationUser.LastName ?? "Default",
        };

        var result = await _userManager.CreateAsync(user, password);
        return result.Succeeded;
    }
}
