defmodule Uketsuke.JSONLog do
  @moduledoc """
  Collects log events as the production JSON formatter renders them, decoded.
  The handler runs in the logging process and forwards each line to the test.
  """

  def capture(fun) do
    id = :"json_log_#{System.unique_integer([:positive])}"
    formatter = LoggerJSON.Formatters.Basic.new(metadata: [])
    :ok = :logger.add_handler(id, __MODULE__, %{config: %{pid: self()}, formatter: formatter})

    try do
      ExUnit.CaptureLog.capture_log(fun)
      drain([])
    after
      :logger.remove_handler(id)
    end
  end

  def requests(lines),
    do: Enum.filter(lines, &match?(%{"message" => %{"event" => "request"}}, &1))

  def log(event, %{config: %{pid: pid}, formatter: {module, config}}) do
    line = event |> module.format(config) |> IO.iodata_to_binary()
    send(pid, {__MODULE__, line})
  end

  defp drain(lines) do
    receive do
      {__MODULE__, line} ->
        [_json, ""] = String.split(line, "\n")
        drain([Jason.decode!(line) | lines])
    after
      0 -> Enum.reverse(lines)
    end
  end
end

ExUnit.start(exclude: [s3: true])
