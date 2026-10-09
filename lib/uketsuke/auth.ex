defmodule Uketsuke.Auth do
  import Plug.Conn, only: [get_req_header: 2]

  @fields ~w(protocol service network campaign pool_id submission_id file_hash file_size filename expires_at)

  def parse!(conn, id, config) do
    require!(hex?(id, 32), 400, "invalid_id", "submission id must be 32 lowercase hex characters")
    encoded = header!(conn, "x-upload-manifest")
    max_encoded = 4 * div(config["max_manifest_bytes"] + 2, 3)

    require!(
      byte_size(encoded) <= max_encoded,
      413,
      "manifest_too_large",
      "manifest exceeds configured limit"
    )

    bytes =
      case Base.decode64(encoded) do
        {:ok, bytes} -> bytes
        :error -> fail!(400, "invalid_manifest", "manifest must use standard padded base64")
      end

    require!(
      Base.encode64(bytes) == encoded,
      400,
      "invalid_manifest",
      "manifest must use standard padded base64"
    )

    require!(
      byte_size(bytes) <= config["max_manifest_bytes"],
      413,
      "manifest_too_large",
      "manifest exceeds configured limit"
    )

    manifest = decode_manifest!(bytes)
    validate_manifest!(manifest, id, config)
    key = header!(conn, "x-upload-key")
    signature = header!(conn, "x-upload-signature")

    require!(
      hex?(key, 192),
      400,
      "invalid_key",
      "public key must be 192 lowercase hex characters"
    )

    require!(
      hex?(signature, 96),
      400,
      "invalid_signature",
      "signature must be 96 lowercase hex characters"
    )

    %{manifest: manifest, bytes: bytes, key: key, signature: signature}
  end

  def authorize!(auth, config) do
    roster_bytes = read_roster!(config)
    roster = decode!(roster_bytes, 503, "roster_unavailable")
    validate_roster!(roster)
    keys = Map.get(roster["pools"], auth.manifest["pool_id"], [])

    require!(
      auth.key in keys,
      403,
      "key_not_registered",
      "key is not registered for this pool in the current roster"
    )

    case Uketsuke.Native.verify(
           Base.decode16!(auth.key, case: :lower),
           Base.decode16!(auth.signature, case: :lower),
           auth.bytes
         ) do
      :verified ->
        Map.put(auth, :roster_bytes, roster_bytes)

      {:rejected, _reason} ->
        fail!(401, "invalid_signature", "BLS signature verification failed")

      {:invalid_key, reason} ->
        require Logger
        Logger.error("roster key for pool #{auth.manifest["pool_id"]} is invalid: #{reason}")
        fail!(503, "verifier_unavailable", "signature verifier is unavailable")
    end
  end

  def immutable(manifest), do: Map.delete(manifest, "expires_at")

  def hex?(value, size) do
    is_binary(value) and byte_size(value) == size and Regex.match?(~r/\A[0-9a-f]+\z/, value)
  end

  def require!(true, _status, _code, _message), do: :ok
  def require!(false, status, code, message), do: fail!(status, code, message)
  def fail!(status, code, message), do: throw({:http_error, status, code, message})

  defp header!(conn, name) do
    case get_req_header(conn, name) do
      [value] -> value
      _ -> fail!(400, "missing_header", "exactly one #{name} header is required")
    end
  end

  defp validate_manifest!(manifest, id, config) do
    require!(
      manifest["protocol"] == "leios-artifact-upload/v1",
      400,
      "wrong_protocol",
      "unsupported manifest protocol"
    )

    Enum.each(~w(service network campaign), fn field ->
      require!(
        manifest[field] == config[field],
        403,
        "wrong_#{field}",
        "manifest #{field} does not match this inbox"
      )
    end)

    require!(
      manifest["submission_id"] == id,
      400,
      "id_mismatch",
      "manifest submission_id does not match request path"
    )

    require!(
      hex?(manifest["pool_id"], 56),
      400,
      "invalid_pool",
      "pool_id must be 56 lowercase hex characters"
    )

    require!(
      hex?(manifest["file_hash"], 64),
      400,
      "invalid_hash",
      "file_hash must be 64 lowercase hex characters"
    )

    size = manifest["file_size"]

    require!(
      is_integer(size) and size > 0,
      400,
      "invalid_size",
      "file_size must be a positive integer"
    )

    require!(
      size <= config["max_file_bytes"],
      413,
      "file_too_large",
      "file_size exceeds configured limit"
    )

    filename = manifest["filename"]

    require!(
      is_binary(filename) and String.valid?(filename) and String.trim(filename) != "",
      400,
      "invalid_filename",
      "filename must be a nonempty UTF-8 display name"
    )

    expires = manifest["expires_at"]
    now = System.system_time(:second)

    require!(
      is_integer(expires),
      400,
      "invalid_expiry",
      "expires_at must be an integer Unix timestamp"
    )

    require!(expires > now, 401, "expired_manifest", "manifest has expired")

    require!(
      expires <= now + config["max_lifetime_secs"],
      400,
      "expiry_too_far",
      "manifest lifetime exceeds configured limit"
    )
  end

  defp read_roster!(config) do
    case File.open(config["roster_path"], [:read, :binary]) do
      {:ok, file} ->
        try do
          # Stat the opened snapshot, not a path that a roster rename can replace.
          with {:ok, record} <- :file.read_file_info(file, time: :posix),
               stat = File.Stat.from_record(record),
               true <- stat.type == :regular,
               age = System.system_time(:second) - stat.mtime,
               true <- age >= 0 and age <= config["roster_max_age_secs"],
               bytes when is_binary(bytes) <- IO.binread(file, :eof) do
            bytes
          else
            _ ->
              fail!(
                503,
                "roster_unavailable",
                "roster is stale, unreadable, or not a regular file"
              )
          end
        after
          File.close(file)
        end

      {:error, _reason} ->
        fail!(503, "roster_unavailable", "roster could not be opened")
    end
  end

  defp validate_roster!(roster) do
    valid =
      is_map(roster) and Enum.sort(Map.keys(roster)) == ~w(epoch pools slot) and
        is_integer(roster["epoch"]) and roster["epoch"] >= 0 and
        is_integer(roster["slot"]) and roster["slot"] >= 0 and is_map(roster["pools"]) and
        Enum.all?(roster["pools"], fn {pool, keys} ->
          hex?(pool, 56) and is_list(keys) and Enum.all?(keys, &hex?(&1, 192))
        end)

    require!(valid, 503, "roster_unavailable", "roster has an invalid schema")
  end

  defp decode!(bytes, status, code) do
    case Jason.decode(bytes) do
      {:ok, value} -> value
      {:error, _reason} -> fail!(status, code, "invalid UTF-8 JSON")
    end
  end

  defp decode_manifest!(bytes) do
    case Jason.decode(bytes, objects: :ordered_objects) do
      {:ok, %Jason.OrderedObject{values: members}} ->
        require!(
          Enum.sort(Enum.map(members, &elem(&1, 0))) == Enum.sort(@fields),
          400,
          "invalid_manifest",
          "manifest must contain each protocol field exactly once"
        )

        Map.new(members)

      {:ok, _value} ->
        fail!(400, "invalid_manifest", "manifest must be a JSON object")

      {:error, _reason} ->
        fail!(400, "invalid_manifest", "invalid UTF-8 JSON")
    end
  end
end
