defmodule Uketsuke.Metrics do
  @moduledoc """
  Prometheus counters and histograms kept in ETS, rendered on the loopback
  metrics listener. Roster and configured-limit gauges are read at scrape time;
  in-flight and reserved-quota gauges are written by the Store and Quota.
  """

  use GenServer
  require Logger

  alias Uketsuke.{Error, Roster}

  @table __MODULE__
  @buckets %{
    request_duration: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
    s3_request_duration: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]
  }
  @families [
    {:requests, "uketsuke_requests_total", "counter",
     "Finished requests by route, outcome and rejection code."},
    {:request_duration, "uketsuke_request_duration_seconds", "histogram",
     "Request duration by route."},
    {:accepted_bytes, "uketsuke_accepted_bytes_total", "counter",
     "Signed ZIP bytes of newly accepted Submissions."},
    {:s3_requests, "uketsuke_s3_requests_total", "counter",
     "S3 requests by operation and HTTP status, error or timeout."},
    {:s3_request_duration, "uketsuke_s3_request_duration_seconds", "histogram",
     "S3 request duration by operation."}
  ]

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl true
  def init(nil) do
    :ets.new(@table, [:named_table, :public, :set, write_concurrency: true])
    # Unlabelled counters exist from the start: 0 is their true initial value.
    :ets.insert(@table, {{:accepted_bytes, []}, 0})
    {:ok, nil}
  end

  def request(route, {outcome, code}, duration) when route in [:upload, :receipt] do
    route = Atom.to_string(route)
    count(:requests, [route: route, outcome: outcome, code: code], 1)
    observe(:request_duration, [route: route], duration)
  end

  def unrouted,
    do: count(:requests, [route: "other", outcome: "rejected", code: "not_found"], 1)

  # Written by the Store on every admission and release, so scrapes never call it.
  def inflight(count) when is_integer(count) and count >= 0,
    do: :ets.insert(@table, {:inflight, count})

  def accepted_bytes(bytes) when is_integer(bytes) and bytes > 0,
    do: count(:accepted_bytes, [], bytes)

  def s3(op, status, duration) when op in [:head, :get, :put] do
    op = Atom.to_string(op)
    count(:s3_requests, [op: op, status: to_string(status)], 1)
    observe(:s3_request_duration, [op: op], duration)
  end

  # Reservations are never reclaimed, so the largest total any ledger read or
  # write saw is the current one; a late, older reading cannot lower it.
  def quota_reserved(bytes) when is_integer(bytes) and bytes >= 0 do
    unless :ets.insert_new(@table, {:quota_reserved, bytes}) do
      raise_to = [{{:quota_reserved, :"$1"}, [{:<, :"$1", bytes}], [{{:quota_reserved, bytes}}]}]
      :ets.select_replace(@table, raise_to)
    end

    :ok
  end

  defp count(family, labels, amount),
    do: :ets.update_counter(@table, {family, labels}, amount, {{family, labels}, 0})

  # Row: {key, count, sum_native, bucket_1, ..., bucket_n}; buckets are not cumulative.
  defp observe(family, labels, duration) do
    bounds = Map.fetch!(@buckets, family)
    seconds = duration / System.convert_time_unit(1, :second, :native)
    index = Enum.find_index(bounds, &(seconds <= &1))
    updates = [{2, 1}, {3, duration} | if(index, do: [{4 + index, 1}], else: [])]
    default = List.to_tuple([{family, labels}, 0, 0 | List.duplicate(0, length(bounds))])
    :ets.update_counter(@table, {family, labels}, updates, default)
  end

  def render(config) do
    rows = :ets.tab2list(@table)

    series =
      Enum.flat_map(@families, fn {family, name, type, help} ->
        samples =
          for row <- rows, match?({^family, _}, elem(row, 0)), do: samples(type, name, row)

        [header(name, type, help) | samples]
      end)

    [series, gauges(config, rows)]
  end

  defp samples("counter", name, {{_family, labels}, value}), do: sample(name, labels, value)

  defp samples("histogram", name, row) do
    [{family, labels}, count, sum | buckets] = Tuple.to_list(row)
    bounds = Map.fetch!(@buckets, family)

    cumulative =
      bounds
      |> Enum.zip(buckets)
      |> Enum.map_reduce(0, fn {bound, n}, acc -> {{bound, acc + n}, acc + n} end)
      |> elem(0)

    [
      for({bound, n} <- cumulative, do: sample(name <> "_bucket", labels ++ [le: bound], n)),
      sample(name <> "_bucket", labels ++ [le: "+Inf"], count),
      sample(name <> "_sum", labels, sum / System.convert_time_unit(1, :second, :native)),
      sample(name <> "_count", labels, count)
    ]
  end

  defp gauges(config, rows) do
    roster =
      try do
        {:ok, Roster.load!(config.roster_path, :cached)}
      rescue
        error in Error ->
          # roster_ok 0 says that it failed; the log says why, on every scrape until fixed.
          Logger.error(%{event: "roster_unavailable", message: Exception.message(error)})
          :unavailable
      end

    {roster_ok, roster_details} =
      case roster do
        {:ok, roster} ->
          {Roster.fresh?(roster, config),
           [
             gauge(
               "uketsuke_roster_mtime_seconds",
               "Key Roster file mtime, Unix seconds.",
               roster.mtime
             ),
             gauge("uketsuke_roster_epoch", "Key Roster snapshot epoch.", roster.epoch),
             gauge("uketsuke_roster_pools", "Pools in the Key Roster.", map_size(roster.pools))
           ]}

        :unavailable ->
          {false, []}
      end

    [
      stored_gauge(rows, :inflight, "uketsuke_inflight", "Admitted in-flight requests."),
      gauge("uketsuke_inflight_max", "Configured max_inflight.", config.max_inflight),
      stored_gauge(
        rows,
        :quota_reserved,
        "uketsuke_quota_reserved_bytes",
        "Ledger-reserved ZIP bytes, the largest total seen by a ledger read or write."
      ),
      gauge("uketsuke_quota_max_bytes", "Configured max_total_bytes.", config.max_total_bytes),
      gauge(
        "uketsuke_roster_ok",
        "1 when the Key Roster is valid and within roster_max_age_secs.",
        if(roster_ok, do: 1, else: 0)
      ),
      roster_details
    ]
  end

  # Absent until written: a made-up 0 would claim an empty ledger or idle Store.
  defp stored_gauge(rows, key, name, help) do
    case List.keyfind(rows, key, 0) do
      {^key, value} -> gauge(name, help, value)
      nil -> []
    end
  end

  defp gauge(name, help, value), do: [header(name, "gauge", help), sample(name, [], value)]

  defp header(name, type, help),
    do: ["# HELP ", name, " ", help, "\n# TYPE ", name, " ", type, "\n"]

  defp sample(name, labels, value) do
    labels =
      for {key, value} <- labels,
          value != nil,
          do: [Atom.to_string(key), "=\"", to_string(value), "\""]

    labels = if labels == [], do: [], else: ["{", Enum.intersperse(labels, ","), "}"]
    [name, labels, " ", number(value), "\n"]
  end

  defp number(value) when is_integer(value), do: Integer.to_string(value)
  defp number(value) when is_float(value), do: :erlang.float_to_binary(value, [:short])
end
