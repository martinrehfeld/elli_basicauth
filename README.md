# Basic Authentication Middleware for Elli

Use it like this:

    PasswordCheck =
        fun (User, Password) ->
            case {User, Password} of
                {undefined, undefined}      -> unauthorized;
                {<<"admin">>, <<"secret">>} -> ok;
                {User, Password}            -> forbidden
            end
        end,

    AuthFun =
        fun (Req, User, Password) ->
                case elli_request:path(Req) of
                    [<<"protected">>] -> PasswordCheck(User, Password);
                    _ ->                 ok
                end
        end,

    BasicauthConfig = [{auth_fun, AuthFun},
                       {auth_realm, <<"Admin Area">>} % optional
                      ],

    Config = [
              {mods, [
                      {elli_basicauth, BasicauthConfig},
                      {elli_example_callback, []}
                     ]}
             ],

    elli:start_link([{callback, elli_middleware}, {callback_args, Config}]).
