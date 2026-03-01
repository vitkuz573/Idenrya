using System.ComponentModel.DataAnnotations;

namespace Idenrya.Server.Models.Account;

public sealed class LoginViewModel
{
    [Required]
    [Display(Name = "Username")]
    public string Login { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public string ReturnUrl { get; set; } = "/";
}
