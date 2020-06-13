# Custom ASP.NET Identity Handling

Once upon a time I thought: "What if I would like to take more control over whole authentication/authorization proccess while making a web app?"
And then I dived into Identity Framework...

#### If you're interested in implementing this in your own project - be careful, I'm not a security expert. Proceed with caution.

Quick overview of what's going on here:

There're 2 projects in solution: **WebAPI** and **Auth**. 
All API-related stuff located in first one, all auth-stuff in second one.

This project uses Postgres. But you can use any SQL database you like.

###### Ok, that was really quick. Now let's dive into details.

So first of all, in this project you'll find 2 working implementations - authentication with cookie and authentication with headers.
Both of them make use of JWT, but in a slightly different way. 

Cookie authentication sets the `http-only` cookie which is sent to client when login is successful. Cookie body looks like that:
`{"accesstoken":"jwt-goes-there","refreshtoken":"jwt-goes-there"}`.
Headers authentication works pretty much the same as the cookie one, but without setting the cookie. 

The proccess behind authentication is simple. Client sents the request (any kind of request, it can be API call, view, etc) and adds token pair to its request (if client uses `Headers Authentication`), or, if a client uses `Cookie Authentication`, then its behavior will not change (because of the cookie). 

The access and refresh token travel together. If a lifetime of an access token is over, then refresh token is checked. If a refresh token is rotten and stinks, then 401 is returned. But, if access token is not valid (lifetime), but refresh token is ok, then a new pair of tokens is sent. (**Note** this behavior is not implemented for headers authentication (yet))

This project allows you two use more than one `Authentication Scheme`. That means you can use infinite amount of authentication handlers. I implemented Cookie and Headers authentication (separately).

__Note__: I didn't make use of all instruments that ASP.NET Core Identity provide. 
For example, such tables as `AspNetRoleClaims`, `AspNetUserLogins`, `AspNetUserTokens` are not used at all.
