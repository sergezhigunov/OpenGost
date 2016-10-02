using System;
using System.Runtime.InteropServices;
using System.Security;

[assembly: ComVisible(false)]
[assembly: Guid("668d7f7f-ce7e-45fb-8cf2-a8ed35d72f3f")]
[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers]
#if NET45
[assembly: SecurityRules(SecurityRuleSet.Level2, SkipVerificationInFullTrust = true)]
#endif