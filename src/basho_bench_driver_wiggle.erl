-module(basho_bench_driver_wiggle).

-export([new/1,
         run/4]).

-include("basho_bench.hrl").

-record(state, {
          proto,
          token,
          hosts,
          base_path,
          version,
          endpoint,
          port,
          base_urls,
          keys = [],
          keys2 = [],
          base_urls_index = 0
         }).

-record(url, {abspath, host, port, username, password, path, protocol, host_type}).


new(_) ->
    %% Make sure ibrowse is available
    case code:which(ibrowse) of
        non_existing ->
            ?FAIL_MSG("~s requires ibrowse to be installed.\n", [?MODULE]);
        _ ->
            ok
    end,

    Proto = case basho_bench_config:get(http_use_ssl, false) of
                false ->
                    "http://";
                _ ->
                    case ssl:start() of
                        ok ->
                            "https://";
                        {error, {already_started, ssl}} ->
                            "https://";
                        _ ->
                            ?FAIL_MSG("Unable to enable SSL support.\n", [])
                    end
            end,
    application:start(ibrowse),
    Disconnect = basho_bench_config:get(http_raw_disconnect_frequency, infinity),
    case Disconnect of
        infinity -> ok;
        Seconds when is_integer(Seconds) -> ok;
        {ops, Ops} when is_integer(Ops) -> ok;
        _ -> ?FAIL_MSG("Invalid configuration for http_raw_disconnect_frequency: ~p~n", [Disconnect])
    end,

    %% Uses pdict to avoid threading state record through lots of functions
    erlang:put(disconnect_freq, Disconnect),

    Token     = basho_bench_config:get(wiggle_token),
    Hosts     = basho_bench_config:get(wiggle_hosts, ["127.0.0.1"]),
    Port      = basho_bench_config:get(wiggle_port, 80),
    BasePath  = basho_bench_config:get(wiggle_base_path, ""),
    Version   = basho_bench_config:get(wiggle_api_version, "0.1.0"),
    Endpoint  = basho_bench_config:get(wiggle_endpoint, "packages"),
    Keys      = basho_bench_config:get(wiggle_initial_keys, []),
    BaseUrls  = list_to_tuple([#url{host = Host,
                                    port = Port,
                                    path = BasePath ++ "/api/" ++ Version ++
                                        "/" ++ Endpoint
                                   } || Host <- Hosts]),
    BaseUrlsIndex = random:uniform(tuple_size(BaseUrls)),

    erlang:put(token, Token),

    {ok, #state{
            base_urls = BaseUrls,
            base_urls_index = BaseUrlsIndex,
            hosts = Hosts,
            port = Port,
            proto = Proto,
            token = Token,
            base_path = BasePath,
            version = Version,
            endpoint = Endpoint,
            keys = Keys}}.

run(get, KeyGen, ValueGen, State=#state{keys = [], keys2 = [_|_] = K2}) ->
    run(get, KeyGen, ValueGen, State#state{keys = K2, keys2 = []});

run(get, _KeyGen, _ValueGen, State=#state{keys = [K | K1], keys2 = K2}) ->
    S1 = State#state{keys = K1, keys2 = [K | K2]},
    {Url, S2} = next_url(S1),
    case do_get(Url#url{path = Url#url.path ++ "/" ++ K}) of
        {not_found, _Url} ->
            {ok, S2};
        {ok, _Url, _Headers} ->
            {ok, S2};
        {error, Reason} ->
            {error, Reason, S2}
    end;

run(get, _KeyGen, _ValueGen, State = #state{keys = [], keys2 = []}) ->
    {error, no_keys, State};

run(list, _KeyGen, _ValueGen, State) ->
    {Url, S1} = next_url(State),
    case do_get(Url) of
        {not_found, _Url} ->
            {ok, S1};
        {ok, _Url, _Headers} ->
            {ok, S1};
        {error, Reason} ->
            {error, Reason, S1}
    end;

run(post,_,_,State) ->
    {ok, State};

run(put,_,_,State) ->
    {ok, State};

run(delete,_,_,State) ->
    {ok, State};

run(_,_,_,State) ->
    {ok, State}.


%% ====================================================================
%% Internal functions
%% ====================================================================

%% check_numfound(Struct, Expected) ->
%%     NumFound = get_path(Struct, [<<"response">>, <<"numFound">>]),
%%     if Expected == NumFound ->
%%             true;
%%        true ->
%%             {false, NumFound}
%%     end.

%% get_path({struct, PL}, Path) ->
%%     get_path(PL, Path);

%% get_path(PL, [Name]) ->
%%     case proplists:get_value(Name, PL) of
%%         {struct, Obj} -> Obj;
%%         Val -> Val
%%     end;
%% get_path(PL, [Name|Path]) ->
%%     get_path(proplists:get_value(Name, PL), Path).

next_url(State) when is_record(State#state.base_urls, url) ->
    {State#state.base_urls, State};
next_url(State) when State#state.base_urls_index > tuple_size(State#state.base_urls) ->
    { element(1, State#state.base_urls),
      State#state { base_urls_index = 1 } };
next_url(State) ->
    { element(State#state.base_urls_index, State#state.base_urls),
      State#state { base_urls_index = State#state.base_urls_index + 1 }}.

%% url(BaseUrl, Params) ->
%%     BaseUrl#url { path = lists:concat([BaseUrl#url.path, Params]) }.
%% url(BaseUrl, KeyGen, Params) when is_function(KeyGen) ->
%%     BaseUrl#url { path = lists:concat([BaseUrl#url.path, '/', KeyGen(), Params]) };
%% url(BaseUrl, Key, Params) ->
%%     BaseUrl#url { path = lists:concat([BaseUrl#url.path, '/', Key, Params]) }.

%% search_url(BaseUrl, SolrPath, SearchGen) ->
%%     Params = if is_function(SearchGen) ->
%%                      SearchGen();
%%                 true ->
%%                      SearchGen
%%              end,
%%     BaseUrl#url { path = lists:concat([SolrPath, '/select?', Params]) }.

do_get(Url) ->
    do_get(Url, []).

do_get(Url, Opts) ->
    case send_request(Url, [], get, [], [{response_format, binary}]) of
        {ok, "404", _Headers, _Body} ->
            {not_found, Url};
        {ok, "300", Headers, _Body} ->
            {ok, Url, Headers};
        {ok, "200", Headers, Body} ->
            case proplists:get_bool(body_on_success, Opts) of
                true -> {ok, Url, Headers, Body};
                false -> {ok, Url, Headers}
            end;
        {ok, Code, _Headers, _Body} ->
            {error, {http_error, Code}};
        {error, Reason} ->
            {error, Reason}
    end.

%% do_put(Url, Headers, ValueGen) ->
%%     Val = if is_function(ValueGen) ->
%%                   ValueGen();
%%              true ->
%%                   ValueGen
%%           end,
%%     case send_request(Url, Headers ++ [{'Content-Type', 'application/octet-stream'}],
%%                       put, Val, [{response_format, binary}]) of
%%         {ok, "204", _Header, _Body} ->
%%             ok;
%%         {ok, Code, _Header, _Body} ->
%%             {error, {http_error, Code}};
%%         {error, Reason} ->
%%             {error, Reason}
%%     end.

%% do_post(Url, Headers, ValueGen) ->
%%     case send_request(Url, Headers ++ [{'Content-Type', 'application/octet-stream'}],
%%                       post, ValueGen(), [{response_format, binary}]) of
%%         {ok, "201", _Header, _Body} ->
%%             ok;
%%         {ok, "204", _Header, _Body} ->
%%             ok;
%%         {ok, Code, _Header, _Body} ->
%%             {error, {http_error, Code}};
%%         {error, Reason} ->
%%             {error, Reason}
%%     end.

%% do_delete(Url, Headers) ->
%%     case send_request(Url, Headers, delete, [], []) of
%%         {ok, "204", _Header, _Body} ->
%%             ok;
%%         {ok, "404", _Header, _Body} ->
%%             ok;
%%         {ok, Code, _Header, _Body} ->
%%             {error, {http_error, Code}};
%%         {error, Reason} ->
%%             {error, Reason}
%%     end.

connect(Url) ->
    case erlang:get({ibrowse_pid, Url#url.host}) of
        undefined ->
            {ok, Pid} = ibrowse_http_client:start({Url#url.host, Url#url.port}),
            erlang:put({ibrowse_pid, Url#url.host}, Pid),
            Pid;
        Pid ->
            case is_process_alive(Pid) of
                true ->
                    Pid;
                false ->
                    erlang:erase({ibrowse_pid, Url#url.host}),
                    connect(Url)
            end
    end.


disconnect(Url) ->
    case erlang:get({ibrowse_pid, Url#url.host}) of
        undefined ->
            ok;
        OldPid ->
            catch(ibrowse_http_client:stop(OldPid))
    end,
    erlang:erase({ibrowse_pid, Url#url.host}),
    ok.

maybe_disconnect(Url) ->
    case erlang:get(disconnect_freq) of
        infinity -> ok;
        {ops, Count} -> should_disconnect_ops(Count,Url) andalso disconnect(Url);
        Seconds -> should_disconnect_secs(Seconds,Url) andalso disconnect(Url)
    end.

should_disconnect_ops(Count, Url) ->
    Key = {ops_since_disconnect, Url#url.host},
    case erlang:get(Key) of
        undefined ->
            erlang:put(Key, 1),
            false;
        Count ->
            erlang:put(Key, 0),
            true;
        Incr ->
            erlang:put(Key, Incr + 1),
            false
    end.

should_disconnect_secs(Seconds, Url) ->
    Key = {last_disconnect, Url#url.host},
    case erlang:get(Key) of
        undefined ->
            erlang:put(Key, erlang:now()),
            false;
        Time when is_tuple(Time) andalso size(Time) == 3 ->
            Diff = timer:now_diff(erlang:now(), Time),
            if
                Diff >= Seconds * 1000000 ->
                    erlang:put(Key, erlang:now()),
                    true;
                true -> false
            end
    end.

clear_disconnect_freq(Url) ->
    case erlang:get(disconnect_freq) of
        infinity -> ok;
        {ops, _Count} -> erlang:put({ops_since_disconnect, Url#url.host}, 0);
        _Seconds -> erlang:put({last_disconnect, Url#url.host}, erlang:now())
    end.

send_request(Url, Headers, Method, Body, Options) ->
    send_request(Url, Headers, Method, Body, Options, 3).

send_request(_Url, _Headers, _Method, _Body, _Options, 0) ->
    {error, max_retries};
send_request(Url, Headers, Method, Body, Options, Count) ->
    Pid = connect(Url),
    Options2 = case basho_bench_config:get(http_use_ssl, false) of
                   false ->
                       Options;
                   true ->
                       [{is_ssl, true}, {ssl_options, []} | Options];
                   SSLOpts when is_list(SSLOpts) ->
                       [{is_ssl, true}, {ssl_options, SSLOpts} | Options]
               end,
    Headers1 = [{"x-snarl-token", erlang:get(token)} | Headers ],
    AppendHeaders = basho_bench_config:get(http_raw_append_headers,[]),
    case catch(ibrowse_http_client:send_req(
                 Pid, Url, Headers1 ++ AppendHeaders, Method, Body, Options2,
                 basho_bench_config:get(http_raw_request_timeout, 5000))) of
        {ok, Status, RespHeaders, RespBody} ->
            maybe_disconnect(Url),
            {ok, Status, RespHeaders, RespBody};

        Error ->
            clear_disconnect_freq(Url),
            disconnect(Url),
            case should_retry(Error) of
                true ->
                    send_request(Url, Headers, Method, Body, Options, Count-1);

                false ->
                    normalize_error(Method, Error)
            end
    end.

should_retry({error, send_failed})       -> true;
should_retry({error, connection_closed}) -> true;
should_retry({'EXIT', {normal, _}})      -> true;
should_retry({'EXIT', {noproc, _}})      -> true;
should_retry(_)                          -> false.

normalize_error(Method, {'EXIT', {timeout, _}})  -> {error, {Method, timeout}};
normalize_error(Method, {'EXIT', Reason})        -> {error, {Method, 'EXIT', Reason}};
normalize_error(Method, {error, Reason})         -> {error, {Method, Reason}}.
