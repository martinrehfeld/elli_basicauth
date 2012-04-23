%% @doc Elli basicauth overview
%%
%% This middleware provides basic authentication to protect
%% Reqs based on a user-configured Predicate

-module(elli_basicauth).
-behaviour(elli_handler).
-export([handle/2, handle_event/3]).


handle(_Req, _Config) ->
    ignore.


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
