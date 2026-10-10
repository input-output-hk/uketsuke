defmodule Uketsuke.Manifest do
  alias Uketsuke.Error

  @fields ~w(protocol service network campaign pool_id submission_id file_hash file_size filename expires_at)
  @receipt_fields ~w(submission_id file_hash file_size pool_id filename)
  @enforce_keys [:fields, :bytes]
  defstruct @enforce_keys

  def decode!(bytes, id, config, now) do
    Error.require!(
      hex?(id, 32),
      "invalid_id",
      "submission id must be 32 lowercase hex characters"
    )

    Error.require!(
      byte_size(bytes) <= config.max_manifest_bytes,
      "manifest_too_large",
      "manifest exceeds configured limit"
    )

    manifest = decode_archive!(bytes)
    fields = manifest.fields

    Enum.each([:service, :network, :campaign], fn field ->
      name = Atom.to_string(field)

      Error.require!(
        fields[name] == Map.fetch!(config, field),
        "wrong_#{name}",
        "manifest #{name} does not match this inbox"
      )
    end)

    Error.require!(
      fields["submission_id"] == id,
      "id_mismatch",
      "manifest submission_id does not match request path"
    )

    Error.require!(
      fields["file_size"] <= config.max_file_bytes,
      "file_too_large",
      "file_size exceeds configured limit"
    )

    Error.require!(fields["expires_at"] > now, "expired_manifest", "manifest has expired")

    Error.require!(
      fields["expires_at"] <= now + config.max_lifetime_secs,
      "expiry_too_far",
      "manifest lifetime exceeds configured limit"
    )

    manifest
  end

  def decode_archive!(bytes) when is_binary(bytes) do
    fields =
      case Jason.decode(bytes, objects: :ordered_objects) do
        {:ok, %Jason.OrderedObject{values: members}} ->
          Error.require!(
            Enum.sort(Enum.map(members, &elem(&1, 0))) == Enum.sort(@fields),
            "invalid_manifest",
            "manifest must contain each protocol field exactly once"
          )

          Map.new(members)

        {:ok, _value} ->
          Error.raise!("invalid_manifest", "manifest must be a JSON object")

        {:error, _reason} ->
          Error.raise!("invalid_manifest", "invalid UTF-8 JSON")
      end

    Error.require!(
      fields["protocol"] == "leios-artifact-upload/v1",
      "wrong_protocol",
      "unsupported manifest protocol"
    )

    Enum.each(~w(service network campaign), fn field ->
      value = fields[field]

      Error.require!(
        is_binary(value) and String.valid?(value) and String.trim(value) != "",
        "invalid_manifest",
        "manifest #{field} must be a nonempty UTF-8 string"
      )
    end)

    Error.require!(
      hex?(fields["submission_id"], 32),
      "invalid_id",
      "submission id must be 32 lowercase hex characters"
    )

    Error.require!(
      hex?(fields["pool_id"], 56),
      "invalid_pool",
      "pool_id must be 56 lowercase hex characters"
    )

    Error.require!(
      hex?(fields["file_hash"], 64),
      "invalid_hash",
      "file_hash must be 64 lowercase hex characters"
    )

    size = fields["file_size"]

    Error.require!(
      is_integer(size) and size > 0,
      "invalid_size",
      "file_size must be a positive integer"
    )

    filename = fields["filename"]

    Error.require!(
      is_binary(filename) and String.valid?(filename) and String.trim(filename) != "",
      "invalid_filename",
      "filename must be a nonempty UTF-8 display name"
    )

    Error.require!(
      is_integer(fields["expires_at"]),
      "invalid_expiry",
      "expires_at must be an integer Unix timestamp"
    )

    %__MODULE__{fields: fields, bytes: bytes}
  end

  def immutable(%__MODULE__{fields: fields}), do: Map.delete(fields, "expires_at")

  def receipt(%__MODULE__{fields: fields}, stored_at) when is_binary(stored_at) do
    fields
    |> Map.take(@receipt_fields)
    |> Map.merge(%{"durability" => "s3", "stored_at" => stored_at})
  end

  def hex?(value, size) do
    is_binary(value) and byte_size(value) == size and Regex.match?(~r/\A[0-9a-f]+\z/, value)
  end
end
