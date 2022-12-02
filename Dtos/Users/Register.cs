using System.ComponentModel.DataAnnotations;

namespace Project.Dtos.Users;

public class Register
{
    [Required]
    [EmailAddress]
    [StringLength(50)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(50, MinimumLength = 6)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [StringLength(50, MinimumLength = 6)]
    public string ConfirmPassword { get; set; } = string.Empty;
}