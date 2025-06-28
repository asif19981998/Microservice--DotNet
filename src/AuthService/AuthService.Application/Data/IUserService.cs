﻿using AuthService.Domain.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Data;

public interface IUserService
{
    Task<bool> RegisterUserAsync(ApplicationUser identity, string password);
}
