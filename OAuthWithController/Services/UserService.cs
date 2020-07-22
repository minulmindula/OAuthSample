using OAuthWithController.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OAuthWithController.Services
{
    public class UserService
    {
        public User GetUserByCredentials(string email, string password)
        {
            List<User> list_user = new List<User>();
            if(email == "email@domain.com" && password == "password")
            {
                User obj = new User();
                obj.Id = "1";
                obj.Name = "TestUser";
                obj.Email = "email@domain.com";
                obj.Password = "";

                return obj;
            }
            else
            {
                return null;
            }
            //if (user != null)
            //{
            //    user.Password = string.Empty;
            //}
        }
    }
}