using System;
using Project.Dtos;

namespace Project.Services
{
    public interface IEmailService
    {
        void SendEmail(EmailDto request);
    }
}

