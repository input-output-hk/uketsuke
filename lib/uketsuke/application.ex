defmodule Uketsuke.Application do
  use Application

  @impl true
  def start(_type, _args) do
    config = Uketsuke.Config.load!()
    s3 = Uketsuke.S3.new(config)

    children = [
      Uketsuke.S3.child_spec(config),
      {Uketsuke.Store, config},
      {Bandit,
       plug: {Uketsuke.Router, {config, s3}},
       scheme: :http,
       ip: {127, 0, 0, 1},
       port: config.port,
       http_1_options: [max_header_length: config.max_header_bytes],
       http_2_options: [enabled: false],
       websocket_options: [enabled: false],
       thousand_island_options: [read_timeout: config.upload_timeout_ms]}
    ]

    case Supervisor.start_link(children, strategy: :one_for_all, name: Uketsuke.Supervisor) do
      {:ok, pid} ->
        IO.puts("UKETSUKE_READY http://127.0.0.1:#{config.port}")
        {:ok, pid}

      error ->
        error
    end
  end
end
