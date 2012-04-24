# Basic Authentication Middleware for Elli

Use it together with the [Elli webserver](https://github.com/knutin/elli)
like this:

```erlang
-module(my_elli_stuff).
-export([start_link/0, auth_fun/3]).

start_link() ->
    BasicauthConfig = [
                       {auth_fun, fun my_elli_stuff:auth_fun/3},
                       {auth_realm, <<"Admin Area">>} % optional
                      ],

    Config = [
              {mods, [
                      {elli_basicauth, BasicauthConfig},
                      {elli_example_callback, []}
                     ]}
             ],

    elli:start_link([{callback, elli_middleware},
                     {callback_args, Config}]).


auth_fun(Req, User, Password) ->
    case elli_request:path(Req) of
        [<<"protected">>] -> password_check(User, Password);
        _                 -> ok
    end.


password_check(User, Password) ->
    case {User, Password} of
        {undefined, undefined}      -> unauthorized;
        {<<"admin">>, <<"secret">>} -> ok;
        {User, Password}            -> forbidden
    end.
```
