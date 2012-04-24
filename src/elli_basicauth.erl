%% @doc Elli basicauth overview
%%
%% This middleware provides basic authentication to protect
%% Reqs based on a user-configured authentication function

-module(elli_basicauth).
-behaviour(elli_handler).
-export([handle/2, handle_event/3]).


handle(Req, Config) ->
    {User, Password} = credentials(Req),

    case apply(auth_fun(Config), [Req, User, Password]) of
        unauthorized ->
            throw({401,
                   [{<<"WWW-Authenticate">>, auth_realm(Config)}],
                   <<"Unauthorized">>});

        forbidden ->
            throw({403, [], <<"Forbidden">>});

        _ ->
            ignore
    end.


handle_event(_, _, _) ->
    ok.


%%
%% INTERNAL HELPERS
%%

auth_fun(Config) ->
    proplists:get_value(auth_fun, Config,
        %% default to forbidden in case of missing auth_fun config
        fun (_Req, _User, _Password) ->
            forbidden
        end).


auth_realm(Config) ->
    Realm = proplists:get_value(auth_realm, Config, <<"Secure Area">>),
    iolist_to_binary([<<"Basic realm=\"">>, Realm, <<"\"">>]).


credentials(Req) ->
    case authorization_header(Req) of
        undefined ->
            {undefined, undefined};

        AuthorizationHeader ->
            credentials_from_header(AuthorizationHeader)
    end.


authorization_header(Req) ->
    elli_request:get_header(<<"Authorization">>, Req).


credentials_from_header(AuthorizationHeader) ->
    case binary:split(AuthorizationHeader, <<$ >>) of
        [<<"Basic">>, EncodedCredentials] ->
            decoded_credentials(EncodedCredentials);

        _ ->
            {undefined, undefined}
    end.


decoded_credentials(EncodedCredentials) ->
    DecodedCredentials = base64:decode(EncodedCredentials),
    case binary:split(DecodedCredentials, <<$:>>) of
        [User, Password] ->
            {User, Password};

        _ ->
            {undefined, undefined}
    end.
