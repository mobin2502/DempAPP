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

        [HttpPost("login")]

        public async Task<ActionResult<AppUser>> Login(LoginDtos loginDtos){
            var user= await _context.Users.SingleOrDefaultAsync(x=>x.UserName==loginDtos.UserName);

            if(user==null) return Unauthorized("Invalid Username!");

            using var hmac=new HMACSHA512(user.PasswordSalt);

            var ComputedHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDtos.Password));

            for (int i=0; i<ComputedHash.Length; i++){
                if(ComputedHash[i]!=user.PasswordHash[i]) return Unauthorized("Invaid Password !");

            }
            return user;

        }


        private async Task<bool>UserExits(string username){
            return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());
        }

    }
}