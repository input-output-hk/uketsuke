defmodule Uketsuke.StoreTest do
  use ExUnit.Case, async: false

  alias Uketsuke.{Error, Metrics, Store}

  @id String.duplicate("a", 32)

  defp unexpected_kill, do: raise("the deadline killed a request that should finish")

  setup do
    start_supervised!(Metrics)

    root =
      Path.join(
        System.tmp_dir!(),
        "uketsuke-store-" <> Base.encode16(:crypto.strong_rand_bytes(8))
      )

    staging = Path.join(root, "staging")
    on_exit(fn -> File.rm_rf!(root) end)
    store = start_supervised!({Store, %{staging_dir: staging, max_inflight: 2}})
    %{staging: staging, store: store}
  end

  test "staging failure answers its own request and leaves the Store running", %{
    staging: staging,
    store: store
  } do
    # A regular file in place of the staging directory fails mkdir even for root.
    File.rm_rf!(staging)
    File.write!(staging, "")
    deadline = System.monotonic_time(:millisecond) + 5000

    error =
      assert_raise Error, fn ->
        Store.with_slot!(@id, deadline, &unexpected_kill/0, fn _token, _stage ->
          flunk("ran without a stage")
        end)
      end

    assert error.code == "storage_failed"
    assert Process.whereis(Store) == store

    File.rm!(staging)
    File.mkdir!(staging)

    assert Store.with_slot!(@id, deadline, &unexpected_kill/0, fn _token, stage ->
             File.dir?(stage)
           end)

    assert File.ls!(staging) == []
  end

  test "cleanup failure is logged, keeps the request's result and releases the ID", %{
    staging: staging,
    store: store
  } do
    deadline = System.monotonic_time(:millisecond) + 5000

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert :published ==
                 Store.with_slot!(@id, deadline, &unexpected_kill/0, fn _token, stage ->
                   locked = Path.join(stage, "locked")
                   File.mkdir!(locked)
                   File.write!(Path.join(locked, "report"), "")
                   File.chmod!(locked, 0o500)
                   # Root bypasses the mode; the test must prove its fault is real.
                   assert {:error, :eacces} = File.write(Path.join(locked, "probe"), "")
                   :published
                 end)
      end)

    assert log =~ "staging_cleanup_failed"
    assert Process.whereis(Store) == store

    assert Store.with_slot!(@id, deadline, &unexpected_kill/0, fn _token, stage ->
             File.dir?(stage)
           end)

    [leaked] = File.ls!(staging)
    assert String.starts_with?(leaked, @id)
    File.chmod!(Path.join([staging, leaked, "locked"]), 0o700)
  end

  test "a deadline kill runs on_kill outside the Store, which survives its crash", %{
    store: store
  } do
    test = self()
    deadline = System.monotonic_time(:millisecond) + 50

    on_kill = fn ->
      send(test, {:on_kill, self()})
      raise "on_kill failure must stay out of the Store"
    end

    ExUnit.CaptureLog.capture_log(fn ->
      {pid, monitor} =
        spawn_monitor(fn ->
          Store.with_slot!(@id, deadline, on_kill, fn _token, _stage ->
            send(test, :admitted)
            Process.sleep(:infinity)
          end)
        end)

      assert_receive :admitted
      assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}, 1000
      assert_receive {:on_kill, runner}, 1000
      refute runner == store
      # Keep capturing until the runner's crash report is out.
      runner_monitor = Process.monitor(runner)
      assert_receive {:DOWN, ^runner_monitor, :process, ^runner, _}, 1000
    end)

    assert Process.whereis(Store) == store
    other = String.duplicate("b", 32)
    assert Store.with_slot!(other, deadline + 5000, &unexpected_kill/0, fn _, _ -> :ok end) == :ok
  end
end
