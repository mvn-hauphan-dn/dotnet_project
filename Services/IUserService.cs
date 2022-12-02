using Project.Dtos.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Project.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Project.Dtos.Emails;

namespace Project.Services
{
    public interface IUserService
    {
        Task<Response> Register(Register register);

        Task<Response> Login(Login login);

        Task<Response> ConfirmEmail(string id, string token);

        Task<Response> SendResetPassword(string email);

        Task<Response> ResetPassword(string email, string token);
    }

    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public UserService(UserManager<User> userManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        public async Task<Response> Register([FromBody] Register register)
        {
            var userExists = await _userManager.FindByEmailAsync(register.Email);

            if (userExists != null)
                return new Response {
                    StatusCode = 400,
                    Errors = new List<String> { "User already exists!" }
                };

            if (register.Password != register.ConfirmPassword)
                return new Response
                {
                    StatusCode = 400,
                    Errors = new List<String> { "Confirm password does't match the password!" }
                };

            User user = new()
            {
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.Email
            };

            var result = await _userManager.CreateAsync(user, register.Password);

            if (!result.Succeeded)
            {
                return new Response
                {
                    StatusCode = 400,
                    Errors = result.Errors.Select(error => error.Description)
                };
            }

            var confirmEmailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            var getBytesConfirmEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);

            var encodedConfirmEmailToken = WebEncoders.Base64UrlEncode(getBytesConfirmEmailToken);

            string url = $"{_configuration["ApplicationUrl"]}/Api/v1/authenticate/confirm-email?email={user.Email}&token={encodedConfirmEmailToken}";

            var emailDto = new EmailDto
            {
                To = user.Email,
                Subject = "Confirm your email",
                Body = $"<h1>Welcome to project!</h1>" + $"<p>Please confirm your email by <a href='{url}'> Clicking here</a></p>"
            };

            _emailService.SendEmail(emailDto);

            return new Response
            {
                StatusCode = 200
            };
        }


        public async Task<Response> Login(Login login)
        {
            var user = await _userManager.FindByEmailAsync(login.Email);

            if (user == null)
                return new Response
                {
                    StatusCode = 404,
                    Errors = new List<String> { "User not found!" }
                };

            var result = await _userManager.CheckPasswordAsync(user, login.Password);

            if (!result)
                return new Response
                {
                    StatusCode = 400,
                    Errors = new List<String> { "Invalid password!" }
                };

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,
                             Guid.NewGuid().ToString())
                };

            foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

            var token = GetToken(authClaims);

            return new Response
            {
                StatusCode = 200,
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo
            };
        }

        public async Task<Response> ConfirmEmail(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return new Response
                {
                    StatusCode = 404,
                    Errors = new List<String> { "User not found!" }
                };

            var decodedConfirmEmailToken = WebEncoders.Base64UrlDecode(token);

            var confirmToken = Encoding.UTF8.GetString(decodedConfirmEmailToken);

            var result = await _userManager.ConfirmEmailAsync(user, confirmToken);

            if (!result.Succeeded)
                return new Response
                {
                    StatusCode = 400,
                    Errors = result.Errors.Select(error => error.Description)
                };

            return new Response
            {
                StatusCode = 200
            };
        }

        public async Task<Response> SendResetPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return new Response {
                    StatusCode = 404,
                    Errors = new List<String> { "User not found!" }
                };

            var resetEmailToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            var getBytesResetEmailToken = Encoding.UTF8.GetBytes(resetEmailToken);

            var encodedResetEmailToken = WebEncoders.Base64UrlEncode(getBytesResetEmailToken);

            string url = $"{_configuration["ApplicationUrl"]}/api/v1/Authenticate/reset-password?email={user.Email}&token={encodedResetEmailToken}";

            var emailDto = new EmailDto
            {
                To = user.Email,
                Subject = "Confirm your email",
                Body = $"<h1>Welcome to project!</h1>" + $"<p>Please confirm your email by <a href='{url}'> Clicking here</a></p>"
            };

            _emailService.SendEmail(emailDto);

            return new Response
            {
                StatusCode = 200
            };
        }

        public async Task<Response> ResetPassword([FromBody] string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return new Response
                {
                    StatusCode = 404,
                    Errors = new List<String> { "User not found!" }
                };

            var decodedConfirmEmailToken = WebEncoders.Base64UrlDecode(token);

            var confirmToken = Encoding.UTF8.GetString(decodedConfirmEmailToken);

            var result = await _userManager.ConfirmEmailAsync(user, confirmToken);

            if (!result.Succeeded)
                return new Response
                {
                    StatusCode = 400,
                    Errors = result.Errors.Select(error => error.Description)
                };

            return new Response
            {
                StatusCode = 200
            };
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }
}

