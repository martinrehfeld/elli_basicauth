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


%%
%% HELPERS
%%

basicauth_config() ->
    [{auth_fun, fun auth_fun/3}].


auth_fun(_Req, undefined, undefined) -> unauthorized;
auth_fun(_Req, ?USER, ?PASSWORD) -> ok;
auth_fun(_Req, _User, _Password) -> forbidden.
