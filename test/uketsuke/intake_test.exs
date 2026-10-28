defmodule Uketsuke.IntakeTest do
  use ExUnit.Case, async: true
  import Plug.Test
  alias Uketsuke.{Error, Intake}

  @config %{progress_interval_ms: 10}

  # The work reports its pid, then waits to be released, so the test decides
  # how long publication takes without sleeping.
  defp publishing(test, result) do
    fn ->
      send(test, {:publishing, self()})
      receive do: (:release -> result.())
    end
  end

  test "sends 103 while publication runs, then returns its value and the conn" do
    conn = conn(:put, "/v1/uploads/x")
    test = self()

    task =
      Task.async(fn ->
        Intake.with_progress(conn, @config, publishing(test, fn -> :stored end))
      end)

    assert_receive {:publishing, worker}

    for _ <- 1..2,
        do: assert_receive({_ref, :inform, {103, [{"x-upload-stage", "publishing"}]}})

    send(worker, :release)
    assert {%Plug.Conn{}, :stored} = Task.await(task)
  end

  test "a failure in publication is raised in the request process" do
    conn = conn(:put, "/v1/uploads/x")
    test = self()

    task =
      Task.async(fn ->
        try do
          Intake.with_progress(
            conn,
            @config,
            publishing(test, fn -> Error.raise!("storage_failed", "S3 down") end)
          )
        rescue
          error in Error -> {:rescued, error.code}
        end
      end)

    assert_receive {:publishing, worker}
    send(worker, :release)
    assert Task.await(task) == {:rescued, "storage_failed"}
  end
end
