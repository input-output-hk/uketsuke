defmodule Uketsuke.RequestLog do
  @moduledoc """
  One structured log report and one metrics update per finished upload or
  receipt request. `pool_id` and `file_size` are the Manifest's claims; they are
  authenticated only when the outcome is accepted or recovered. Never put
  Manifest bytes, keys or signatures here.
  """

  require Logger
  alias Uketsuke.{Manifest, Metrics}

  @enforce_keys [:route, :started, :submission_id, :pool_id, :file_size]
  defstruct @enforce_keys

  def start(route, id) when route in [:upload, :receipt] do
    %__MODULE__{
      route: route,
      started: System.monotonic_time(),
      submission_id: if(Manifest.hex?(id, 32), do: id),
      pool_id: nil,
      file_size: nil
    }
  end

  def manifest(%__MODULE__{} = log, %Manifest{fields: fields}),
    do: %{log | pool_id: fields["pool_id"], file_size: fields["file_size"]}

  # status is nil when the request process was killed or crashed before answering.
  def finish(%__MODULE__{} = log, result, status) do
    duration = System.monotonic_time() - log.started
    report = report(log, result, status, duration)
    Metrics.request(log.route, {report.outcome, report[:code]}, duration)
    if result == :accepted, do: Metrics.accepted_bytes(log.file_size)
    Logger.info(report)
  end

  def report(%__MODULE__{} = log, result, status, duration) do
    {outcome, code} =
      case result do
        :accepted -> {"accepted", nil}
        :recovered -> {"recovered", nil}
        {:rejected, code} when is_binary(code) -> {"rejected", code}
      end

    %{
      event: "request",
      route: Atom.to_string(log.route),
      outcome: outcome,
      code: code,
      status: status,
      pool_id: log.pool_id,
      submission_id: log.submission_id,
      file_size: log.file_size,
      duration_ms: System.convert_time_unit(duration, :native, :millisecond)
    }
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end
end
