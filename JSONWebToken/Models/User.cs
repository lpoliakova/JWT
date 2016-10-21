using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace JSONWebToken.Models
{
    public class User
    {
        [Required]
        [Display(Name = "User name")]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "User app")]
        public string App { get; set; }

        [Required]
        [Display(Name = "User device")]
        public string Device { get; set; }
    }
}