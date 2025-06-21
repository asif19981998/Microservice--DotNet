using MediatR;

namespace AuthService.Application.Auth.Commands.UserRegistration;

public class UserRegistrationHandler()
    : IRequestHandler<UserRegistrationCommand, UserRegistrationResult>
{
    public Task<UserRegistrationResult> Handle(UserRegistrationCommand request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
