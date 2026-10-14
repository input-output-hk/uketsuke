defmodule Uketsuke.Application do
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    # One JSON object per line, crash reports included, for Loki's `| json`.
    # Set here, not in config: Mix starts Logger before it loads config.
    formatter = LoggerJSON.Formatters.Basic.new(metadata: [])

    case :logger.update_handler_config(:default, :formatter, formatter) do
      :ok ->
        :ok

      {:error, reason} ->
        raise "cannot install the JSON log formatter on the :default logger handler: #{inspect(reason)}"
    end

    config = Uketsuke.Config.load!()
    s3 = Uketsuke.S3.new(config)

    children = [
      Uketsuke.Metrics,
      Uketsuke.S3.child_spec(config),
      Supervisor.child_spec({Task, fn -> observe_quota(s3, config) end}, id: :quota_reading),
      {Uketsuke.Store, config},
      listener(:metrics, config.metrics_port, plug: {Uketsuke.MetricsRouter, config}),
      listener(:http, config.port,
        plug: {Uketsuke.Router, {config, s3}},
        http_1_options: [max_header_length: config.max_header_bytes],
        thousand_island_options: [read_timeout: config.upload_timeout_ms]
      )
    ]

    case Supervisor.start_link(children, strategy: :one_for_all, name: Uketsuke.Supervisor) do
      {:ok, pid} ->
        IO.puts(
          "UKETSUKE_READY http://127.0.0.1:#{bound_port(pid, :http)} " <>
            "metrics=http://127.0.0.1:#{bound_port(pid, :metrics)}/metrics"
        )

        {:ok, pid}

      error ->
        error
    end
  end

  defp listener(id, port, options) do
    options =
      [
        scheme: :http,
        ip: {127, 0, 0, 1},
        port: port,
        http_2_options: [enabled: false],
        websocket_options: [enabled: false]
      ] ++ options

    Supervisor.child_spec({Bandit, options}, id: id)
  end

  defp bound_port(supervisor, id) do
    {^id, pid, _, _} = List.keyfind(Supervisor.which_children(supervisor), id, 0)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    port
  end

  # The gauge stays absent until a ledger read succeeds; startup must not wait on S3.
  defp observe_quota(s3, config) do
    Uketsuke.Quota.observe!(s3, config)
  rescue
    error in Uketsuke.Error ->
      Logger.error(%{
        event: "quota_startup_read_failed",
        code: error.code,
        message: Exception.message(error)
      })
  end
end
