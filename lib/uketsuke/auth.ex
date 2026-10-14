defmodule Uketsuke.Auth do
  import Plug.Conn, only: [get_req_header: 2]
  alias Uketsuke.{Error, Manifest, Native, Roster}
  require Logger

  def parse!(conn, id, config) do
    Error.require!(
      Manifest.hex?(id, 32),
      "invalid_id",
      "submission id must be 32 lowercase hex characters"
    )

    encoded = header!(conn, "x-upload-manifest")

    Error.require!(
      byte_size(encoded) <= config.max_encoded_manifest_bytes,
      "manifest_too_large",
      "manifest exceeds configured limit"
    )

    bytes =
      case Base.decode64(encoded) do
        {:ok, bytes} -> bytes
        :error -> Error.raise!("invalid_manifest", "manifest must use standard padded base64")
      end

    Error.require!(
      Base.encode64(bytes) == encoded,
      "invalid_manifest",
      "manifest must use standard padded base64"
    )

    manifest = Manifest.decode!(bytes, id, config, System.system_time(:second))
    key = header!(conn, "x-upload-key")
    signature = header!(conn, "x-upload-signature")

    Error.require!(
      Manifest.hex?(key, 192),
      "invalid_key",
      "public key must be 192 lowercase hex characters"
    )

    Error.require!(
      Manifest.hex?(signature, 96),
      "invalid_signature_encoding",
      "signature must be 96 lowercase hex characters"
    )

    %{manifest: manifest, bytes: bytes, key: key, signature: signature}
  end

  def authorize!(auth, config) do
    roster = Roster.read!(config, :parse)
    pool = auth.manifest.fields["pool_id"]
    keys = Map.get(roster.pools, pool, [])

    Error.require!(
      auth.key in keys,
      "key_not_registered",
      "key is not registered for this pool in the current roster"
    )

    case Native.verify(
           Base.decode16!(auth.key, case: :lower),
           Base.decode16!(auth.signature, case: :lower),
           auth.bytes
         ) do
      :verified ->
        Map.put(auth, :roster, %{epoch: roster.epoch, slot: roster.slot})

      {:rejected, _reason} ->
        Error.raise!("invalid_signature", "BLS signature verification failed")

      {:invalid_key, reason} ->
        Logger.error("roster key for pool #{pool} is invalid: #{reason}")
        Error.raise!("verifier_unavailable", "signature verifier is unavailable")
    end
  end

  defp header!(conn, name) do
    case get_req_header(conn, name) do
      [value] -> value
      _ -> Error.raise!("missing_header", "exactly one #{name} header is required")
    end
  end
end
