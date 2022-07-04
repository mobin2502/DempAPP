using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {

        private readonly DataContext _context;

        public AccountController(DataContext context)
        {
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDtos registerDtos){
            if (await UserExits(registerDtos.UserName)) return BadRequest("Username is taken");

            using var hmac=new HMACSHA512();
            var user=new AppUser{
                UserName=registerDtos.UserName.ToString(),
                PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDtos.Password)),
                PasswordSalt=hmac.Key
            
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            return user;
        }
    private async Task<bool>UserExits(string username){
        return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());
    }

    }
}