using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.IISIntegration;

namespace SingleSignOnTemplate.Settings
{
    public class AccountOptions
    {
        public bool AllowLocalLogin { get; set; } = true;
        public bool AllowRememberLogin { get; set; } = true;
        public TimeSpan RememberMeLoginDuration { get; set; } = TimeSpan.FromDays(30);

        public bool ShowLogoutPrompt { get; set; } = true;
        public bool AutomaticRedirectAfterSignOut { get; set; } = false;

        public string InvalidCredentialsErrorMessage { get; set; } = "Invalid username or password";
    }
}
