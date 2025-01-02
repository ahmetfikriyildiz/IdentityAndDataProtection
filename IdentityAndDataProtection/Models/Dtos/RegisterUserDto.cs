using System.ComponentModel.DataAnnotations;

namespace IdentityAndDataProtection.Models.Dtos
{
    public class RegisterUserDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }
    }
}
