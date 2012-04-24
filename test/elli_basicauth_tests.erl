-module(elli_basicauth_tests).
-include_lib("eunit/include/eunit.hrl").

-define(USER, <<"Aladdin">>).
-define(PASSWORD, <<"open sesame">>).
-define(VALID_CREDENTIALS, <<"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==">>).
-define(INVALID_CREDENTIALS, <<"Basic cGxhaW46d3Jvbmc=">>).

%%
%% TESTS
%%

no_credentials_test() ->
    meck:new(elli_request),
    meck:expect(elli_request, get_header,
        fun (<<"Authorization">>, mock_request) ->
            undefined
        end),

    Result = (catch elli_basicauth:handle(mock_request,
                                          basicauth_config())),

    ?assertEqual({401,
                  [{<<"WWW-Authenticate">>,
                    <<"Basic realm=\"Secure Area\"">>}],
                  <<"Unauthorized">>}, Result),
    ?assert(meck:validate(elli_request)),
    meck:unload(elli_request).


no_credentials_with_custom_realm_test() ->
    meck:new(elli_request),
    meck:expect(elli_request, get_header,
        fun (<<"Authorization">>, mock_request) ->
            undefined
        end),

    Result =
        (catch elli_basicauth:handle(mock_request,
                                     basicauth_config_with_custom_realm())),

    ?assertEqual({401,
                  [{<<"WWW-Authenticate">>,
                    <<"Basic realm=\"Members only\"">>}],
                  <<"Unauthorized">>}, Result),
    ?assert(meck:validate(elli_request)),
    meck:unload(elli_request).


valid_credentials_test() ->
    meck:new(elli_request),
    meck:expect(elli_request, get_header,
        fun (<<"Authorization">>, mock_request) ->
            ?VALID_CREDENTIALS
        end),

    Result = elli_basicauth:handle(mock_request,
                                   basicauth_config()),

    ?assertEqual(ignore, Result),
    ?assert(meck:validate(elli_request)),
    meck:unload(elli_request).


invalid_credentials_test() ->
    meck:new(elli_request),
    meck:expect(elli_request, get_header,
        fun (<<"Authorization">>, mock_request) ->
            ?INVALID_CREDENTIALS
        end),

    Result = (catch elli_basicauth:handle(mock_request,
                                          basicauth_config())),

    ?assertEqual({403, [], <<"Forbidden">>}, Result),
    ?assert(meck:validate(elli_request)),
    meck:unload(elli_request).


elli_handler_behaviour_test() ->
    ?assertEqual(ok, elli_basicauth:handle_event(request_complete,
                         [mock_request,
                          mock_response_code,
                          mock_response_headers,
                          mock_response_body,
                          mock_timings], mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(request_throw,
                         mock_dummy, mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(request_exit,
                         mock_dummy, mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(request_error,
                         mock_dummy, mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(request_parse_error,
                         [mock_data], mock_args)),

    ?assertEqual(ok, elli_basicauth:handle_event(client_closed,
                         [mock_when], mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(client_timeout,
                         [mock_when], mock_config)),

    ?assertEqual(ok, elli_basicauth:handle_event(elli_startup,
                         [], mock_config)).


%%
%% HELPERS
%%

basicauth_config() ->
    [{auth_fun, fun auth_fun/3}].


basicauth_config_with_custom_realm() ->
    [{auth_fun, fun auth_fun/3},
     {auth_realm, <<"Members only">>}].


auth_fun(_Req, undefined, undefined) -> unauthorized;
auth_fun(_Req, ?USER, ?PASSWORD) -> ok;
auth_fun(_Req, _User, _Password) -> forbidden.
