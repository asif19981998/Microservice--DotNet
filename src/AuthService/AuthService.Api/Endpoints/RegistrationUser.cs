using AuthService.Application.Auth.Commands.UserRegistration;
using AuthService.Application.Dtos;
using Carter;
using Mapster;
using MediatR;

namespace AuthService.Api.Endpoints;

public record UserRegistrationRequest(UserRegistrationDto UserRegistrationDto);
public record UserRegistrationResponse(string UserId, string Message);

public class RegistrationUser : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
       app.MapPost("/register", async (UserRegistrationRequest request,ISender sender) =>
        {
            var command = request.Adapt<UserRegistrationCommand>();

            var result = await sender.Send(command);

            var response = result.Adapt<UserRegistrationResponse>();

            return Results.Ok("User registered successfully.");
        });
    }
}
