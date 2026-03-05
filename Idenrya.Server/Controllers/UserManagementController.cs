using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[Route("api/admin/users")]
[Authorize(Roles = IdentityRoles.Administrator)]
public sealed class UserManagementController(
    IIdentityProviderUserService userService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<OpenIdUserResponse>>> List(CancellationToken cancellationToken)
    {
        return Ok(await userService.ListAsync(cancellationToken));
    }

    [HttpGet("{userName}")]
    public async Task<ActionResult<OpenIdUserResponse>> GetByUserName(
        string userName,
        CancellationToken cancellationToken)
    {
        var user = await userService.FindByUserNameAsync(userName, cancellationToken);
        return user is null ? NotFound() : Ok(user);
    }

    [HttpPost]
    public async Task<ActionResult<OpenIdUserResponse>> Create(
        [FromBody] CreateOpenIdUserRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var created = await userService.CreateAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetByUserName), new { userName = created.UserName }, created);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "User operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpPut("{userName}")]
    public async Task<ActionResult<OpenIdUserResponse>> Update(
        string userName,
        [FromBody] UpdateOpenIdUserRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var updated = await userService.UpdateAsync(userName, request, cancellationToken);
            return updated is null ? NotFound() : Ok(updated);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "User operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpDelete("{userName}")]
    public async Task<IActionResult> Delete(string userName, CancellationToken cancellationToken)
    {
        try
        {
            return await userService.DeleteAsync(userName, cancellationToken) ? NoContent() : NotFound();
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
    }
}
