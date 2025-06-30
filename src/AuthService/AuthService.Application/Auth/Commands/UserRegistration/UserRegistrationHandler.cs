using AuthService.Application.Data;
using AuthService.Domain.Models;
using MediatR;
using Microsoft.AspNetCore.Identity;


namespace AuthService.Application.Auth.Commands.UserRegistration;

public class UserRegistrationHandler : IRequestHandler<UserRegistrationCommand, UserRegistrationResult>
{
    private readonly IUserService _userService;

    public UserRegistrationHandler(IUserService userService)
    {
        _userService = userService;
    }

    public async Task<UserRegistrationResult> Handle(UserRegistrationCommand request, CancellationToken cancellationToken)
    {
        var applicationUser = new ApplicationUser
        {
            UserName = request.UserRegistrationDto.Username,
            Email = request.UserRegistrationDto.Email
        };

        var result = await _userService.RegisterUserAsync(applicationUser, request.UserRegistrationDto.Password);

        //if (!result.Succeeded)
        //{
        //    return new UserRegistrationResult
        //    {
        //        Success = false,
        //        Errors = result.Errors.Select(e => e.Description).ToList()
        //    };
        //}

        //return new UserRegistrationResult
        //{
        //    Success = true
        //};

        return null;
    }
}
