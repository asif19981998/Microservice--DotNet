using AuthService.Application.Dtos;
using MediatR;
using System.Windows.Input;

namespace AuthService.Application.Auth.Commands.UserRegistration;

public record UserRegistrationCommand(UserRegistrationDto UserRegistrationDto) 
    : IRequest<UserRegistrationResult>;

public record UserRegistrationResult(string UserId, string Message);
//public class UserRegistrationCommand : AbstractValidator<UserRegistrationCommand>
//{
//}
