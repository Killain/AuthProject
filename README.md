# Custom ASP.NET Identity Handling

Once upon a time I thought: "What if I would like to take more control over whole authentication/authorization proccess while making a web app?"
And then I dived into Identity Framework...

#### If you're interested in implementing this in your own project - be careful, I'm __not__ a security expert. Proceed with caution.

Quick overview of what's going on here:

There're 2 projects in solution: **WebAPI** and **Auth**. 
All API-related stuff located in first one, all auth-stuff in second one.

This project allows you two use more than one `Authentication Scheme`, that means you can use Cookie and Headers authentication (separately).

__Note__: I didn't make use of all instruments that ASP.NET Core Identity provide. 
For example, such tables as `AspNetRoleClaims`, `AspNetUserLogins`, `AspNetUserTokens` are not used at all.
