defmodule Uketsuke.Quota do
  alias Uketsuke.{Error, Manifest, Metrics, S3}

  @immutable_fields ~w(protocol service network campaign pool_id submission_id file_hash file_size filename)

  def reserve!(s3, config, %Manifest{} = manifest, receipt) do
    immutable = Manifest.immutable(manifest)

    validate_entry!(
      manifest.fields["submission_id"],
      %{"immutable" => immutable, "receipt" => receipt},
      config
    )

    reserve!(s3, config, immutable, receipt, now() + config.s3_timeout_ms)
  end

  # Recovery of a published Bundle: its reservation was written before the
  # Bundle PUT, so a missing ledger or entry is corruption, never a new grant.
  def fetch!(s3, config, %Manifest{} = manifest) do
    immutable = Manifest.immutable(manifest)
    id = immutable["submission_id"]

    ledger =
      case S3.get!(s3, config.s3_prefix <> "quota.json") do
        :missing -> corrupt!("ledger is missing while bundle #{id} exists")
        %{body: body} -> decode!(body, config)
      end

    case Map.fetch(ledger["reservations"], id) do
      {:ok, %{"immutable" => ^immutable, "receipt" => receipt}} -> receipt
      {:ok, _} -> corrupt!("reservation #{id} differs from its bundle's immutable metadata")
      :error -> corrupt!("no reservation for published bundle #{id}")
    end
  end

  defp reserve!(s3, config, immutable, receipt, deadline) do
    key = config.s3_prefix <> "quota.json"
    {ledger, condition} = read!(within_deadline!(s3, deadline), key, config)
    id = immutable["submission_id"]

    case Map.fetch(ledger["reservations"], id) do
      {:ok, entry} ->
        Error.require!(
          entry["immutable"] == immutable,
          "submission_conflict",
          "submission id already names different immutable metadata"
        )

        entry["receipt"]

      :error ->
        used = reserved_bytes(ledger)

        Error.require!(
          used + immutable["file_size"] <= config.max_total_bytes,
          "storage_quota",
          "archive byte quota exhausted"
        )

        entry = %{"immutable" => immutable, "receipt" => receipt}
        updated = put_in(ledger["reservations"][id], entry)
        bytes = Jason.encode!(updated)

        Error.require!(
          byte_size(bytes) <= S3.small_object_limit(s3),
          "storage_failed",
          "quota ledger exceeds the configured small-object bound"
        )

        case S3.put!(within_deadline!(s3, deadline), key, bytes, condition) do
          :ok ->
            Metrics.quota_reserved(used + immutable["file_size"])
            receipt

          :precondition_failed ->
            reserve!(s3, config, immutable, receipt, deadline)
        end
    end
  end

  defp within_deadline!(s3, deadline) do
    remaining = deadline - now()
    Error.require!(remaining > 0, "storage_failed", "quota coordination deadline exceeded")
    %{s3 | timeout: remaining}
  end

  defp now, do: System.monotonic_time(:millisecond)

  # Startup reading for the reserved-bytes gauge; a missing ledger reserves nothing.
  def observe!(s3, config) do
    read!(s3, config.s3_prefix <> "quota.json", config)
    :ok
  end

  defp read!(s3, key, config) do
    case S3.get!(s3, key) do
      :missing ->
        Metrics.quota_reserved(0)
        {%{"version" => 1, "reservations" => %{}}, :absent}

      %{etag: etag, body: body} ->
        {decode!(body, config), {:match, etag}}
    end
  end

  defp reserved_bytes(ledger) do
    Enum.reduce(ledger["reservations"], 0, fn {_id, entry}, sum ->
      sum + entry["immutable"]["file_size"]
    end)
  end

  defp decode!(bytes, config) do
    ledger = decode_ledger!(bytes, config)
    Metrics.quota_reserved(reserved_bytes(ledger))
    ledger
  end

  defp decode_ledger!(bytes, config) do
    ledger =
      case Jason.decode(bytes, objects: :ordered_objects) do
        {:ok, value} -> unique_objects!(value)
        {:error, reason} -> corrupt!("invalid JSON: #{inspect(reason)}")
      end

    exact_fields!(ledger, ~w(version reservations), "ledger")
    if ledger["version"] != 1, do: corrupt!("unsupported version #{inspect(ledger["version"])}")
    if not is_map(ledger["reservations"]), do: corrupt!("reservations is not an object")
    Enum.each(ledger["reservations"], fn {id, entry} -> validate_entry!(id, entry, config) end)
    ledger
  end

  defp unique_objects!(%Jason.OrderedObject{values: members}) do
    keys = Enum.map(members, &elem(&1, 0))
    if length(keys) != MapSet.size(MapSet.new(keys)), do: corrupt!("duplicate JSON object key")
    Map.new(members, fn {key, value} -> {key, unique_objects!(value)} end)
  end

  defp unique_objects!(values) when is_list(values), do: Enum.map(values, &unique_objects!/1)
  defp unique_objects!(value), do: value

  defp validate_entry!(id, entry, config) do
    if not Manifest.hex?(id, 32), do: corrupt!("invalid submission id #{inspect(id)}")
    exact_fields!(entry, ~w(immutable receipt), "reservation #{id}")
    immutable = entry["immutable"]
    exact_fields!(immutable, @immutable_fields, "immutable metadata for #{id}")
    if immutable["submission_id"] != id, do: corrupt!("reservation id differs from immutable id")

    manifest =
      try do
        immutable |> Map.put("expires_at", 0) |> Jason.encode!() |> Manifest.decode_archive!()
      rescue
        error in Error -> corrupt!("invalid immutable metadata for #{id}: #{error.message}")
      end

    Enum.each([:service, :network, :campaign], fn field ->
      name = Atom.to_string(field)

      if immutable[name] != Map.fetch!(config, field),
        do: corrupt!("#{name} differs from inbox configuration")
    end)

    receipt = entry["receipt"]
    if not is_map(receipt), do: corrupt!("receipt for #{id} is not an object")
    stored_at = receipt["stored_at"]
    valid_time = is_binary(stored_at) and match?({:ok, _, 0}, DateTime.from_iso8601(stored_at))
    if not valid_time, do: corrupt!("receipt for #{id} has invalid stored_at")

    if receipt != Manifest.receipt(manifest, stored_at),
      do: corrupt!("receipt differs from immutable metadata for #{id}")

    :ok
  end

  defp exact_fields!(value, fields, label) do
    if not is_map(value) or Enum.sort(Map.keys(value)) != Enum.sort(fields),
      do: corrupt!("#{label} has invalid fields")
  end

  defp corrupt!(message), do: Error.raise!("storage_failed", "corrupt quota ledger: " <> message)
end
