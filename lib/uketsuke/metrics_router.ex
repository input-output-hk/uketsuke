defmodule Uketsuke.MetricsRouter do
  @moduledoc "Loopback-only Prometheus endpoint; never mounted on the public listener."
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(config), do: config

  @impl true
  def call(%{method: "GET", path_info: ["metrics"]} = conn, config) do
    conn
    |> put_resp_content_type("text/plain; version=0.0.4")
    |> send_resp(200, Uketsuke.Metrics.render(config))
  end

  def call(conn, _config), do: send_resp(conn, 404, "")
end
