﻿using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using Project.Dtos.Emails;

namespace Project.Services
{
    public interface IEmailService
    {
        void SendEmail(EmailDto request);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void SendEmail(EmailDto request)
        {
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse("Anonymous"));
            email.To.Add(MailboxAddress.Parse(request.To));
            email.Subject = request.Subject;
            email.Body = new TextPart(TextFormat.Html) { Text = request.Body };

            using var smtp = new SmtpClient();
            smtp.Connect(_configuration["EmailHost"], 587, SecureSocketOptions.StartTls);
            smtp.Authenticate(_configuration["EmailUserName"], _configuration["EmailPassword"]);
            smtp.Send(email);
            smtp.Disconnect(true);
        }
    }
}

