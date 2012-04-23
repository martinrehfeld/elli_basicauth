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
                   [{<<"WWW-Authenticate">>,
                     <<"Basic realm=\"Secure Area\"">>}],
                   <<"Unauthorized">>});

        forbidden ->
            throw({403, [], <<"Forbidden">>});

        _ ->
            ignore
    end.


handle_event(request_complete, [_Req, _ResponseCode, _ResponseHeaders,
                                _ResponseBody, _Timings], _Config) ->
    ok;

handle_event(request_throw, _, _Config) ->
    ok;

handle_event(request_exit, _, _Config) ->
    ok;

handle_event(request_error, _, _Config) ->
    ok;

handle_event(request_parse_error, [_Data], _Args) ->
    ok;

handle_event(client_closed, [_When], _Config) ->
    ok;

handle_event(client_timeout, [_When], _Config) ->
    ok;

handle_event(elli_startup, [], _Config) ->
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


credentials(Req) ->
    case authorization_header(Req) of
        undefined ->
            {undefined, undefined};

        AuthorizationHeader ->
            credentials_from_header(AuthorizationHeader)
    end.


authorization_header(Req) ->
    elli:get_header(<<"Authorization">>, Req).


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
