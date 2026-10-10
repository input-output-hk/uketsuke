defmodule Uketsuke.Bundle do
  @moduledoc """
  Immutable four-entry, uncompressed POSIX USTAR evidence bundles.

  Reports are copied and hashed in 64 KiB chunks. The signed manifest keeps its
  exact bytes. The attestation names the Key Roster snapshot (epoch and slot)
  that authorized the key; the roster itself is chain data and is not copied.
  """
  alias Uketsuke.{Error, Manifest, Native}

  @names ~w(report.zip manifest.json attestation.json receipt.json)
  @zero <<0::4096>>
  @chunk 64 * 1024
  @max_size 8_589_934_591

  def create!(stage, %{manifest: %Manifest{} = manifest} = auth, receipt) do
    storage!(fn ->
      Error.require!(
        auth.bytes == manifest.bytes,
        "storage_failed",
        "manifest bytes do not match authorization"
      )

      validate_receipt!(manifest, receipt)

      attestation = %{
        public_key: auth.key,
        signature: auth.signature,
        roster_epoch: auth.roster.epoch,
        roster_slot: auth.roster.slot
      }

      write_bundle!(stage, auth, receipt, Jason.encode!(attestation))
    end)
  end

  def load!(tar_path) do
    storage!(fn ->
      regular!(tar_path)

      with_file!(tar_path, [:read, :binary, :raw], fn file ->
        size = opened_size!(file)

        Error.require!(
          rem(size, 512) == 0,
          "storage_failed",
          "bundle length is not a multiple of a tar block"
        )

        entries = read_entries!(file, size, %{})
        manifest = Manifest.decode_archive!(Map.fetch!(entries, "manifest.json"))
        validate_report!(manifest, Map.fetch!(entries, "report.zip"))
        receipt = json!(Map.fetch!(entries, "receipt.json"))
        validate_receipt!(manifest, receipt)
        attested = attested!(manifest, Map.fetch!(entries, "attestation.json"))
        Map.merge(%{manifest: manifest, receipt: receipt}, attested)
      end)
    end)
  end

  defp write_bundle!(stage, auth, receipt, attestation) do
    report = Path.join(stage, "report.zip")
    regular!(report)
    path = Path.join(stage, "bundle.tar.tmp")

    with_file!(path, [:write, :binary, :raw, :exclusive], fn output ->
      File.chmod!(path, 0o600)

      with_file!(report, [:read, :binary, :raw], fn input ->
        size = opened_size!(input)
        write!(output, header!("report.zip", size))
        summary = transfer!(input, output, size, :crypto.hash_init(:sha256))
        Error.require!(read!(input, 1) == :eof, "storage_failed", "report changed while bundling")
        validate_report!(auth.manifest, summary)
        write!(output, zeros(padding(size)))
      end)

      Enum.each(
        [
          {"manifest.json", auth.bytes},
          {"attestation.json", attestation},
          {"receipt.json", Jason.encode!(receipt)}
        ],
        fn {name, bytes} ->
          write!(output, [
            header!(name, byte_size(bytes)),
            bytes,
            zeros(padding(byte_size(bytes)))
          ])
        end
      )

      write!(output, [@zero, @zero])
    end)

    final = Path.join(stage, "bundle.tar")
    File.rename!(path, final)
    final
  end

  defp read_entries!(file, remaining, entries) do
    Error.require!(remaining >= 512, "storage_failed", "bundle is missing tar end markers")
    header = exact!(file, 512)

    if header == @zero do
      Error.require!(
        remaining >= 1024 and exact!(file, 512) == @zero,
        "storage_failed",
        "bundle is missing the second tar end marker"
      )

      zero_tail!(file, remaining - 1024)

      Error.require!(
        Enum.sort(Map.keys(entries)) == Enum.sort(@names),
        "storage_failed",
        "bundle must contain exactly the four evidence files"
      )

      entries
    else
      {name, size} = parse_header!(header)

      Error.require!(
        not Map.has_key?(entries, name),
        "storage_failed",
        "bundle contains duplicate entry #{name}"
      )

      padded = size + padding(size)

      Error.require!(
        padded <= remaining - 512,
        "storage_failed",
        "tar entry #{name} exceeds the remaining bundle bytes"
      )

      value =
        if name == "report.zip" do
          transfer!(file, nil, size, :crypto.hash_init(:sha256))
        else
          read_metadata!(file, size, [])
        end

      Error.require!(
        exact!(file, padding(size)) == zeros(padding(size)),
        "storage_failed",
        "tar entry #{name} has nonzero padding"
      )

      read_entries!(file, remaining - 512 - padded, Map.put(entries, name, value))
    end
  end

  defp parse_header!(header) do
    <<name::binary-size(100), _mode::binary-size(8), _uid::binary-size(8), _gid::binary-size(8),
      size::binary-size(12), _mtime::binary-size(12), checksum::binary-size(8), type,
      link::binary-size(100), magic::binary-size(6), version::binary-size(2),
      _owner::binary-size(32), _group::binary-size(32), _major::binary-size(8),
      _minor::binary-size(8), prefix::binary-size(155), _rest::binary-size(12)>> = header

    expected = header |> replace_checksum() |> checksum()

    Error.require!(
      octal!(checksum) == expected,
      "storage_failed",
      "tar header checksum does not match"
    )

    Error.require!(
      magic == "ustar\0" and version == "00",
      "storage_failed",
      "bundle must use POSIX USTAR headers"
    )

    Error.require!(
      type in [0, ?0] and all_zero?(link),
      "storage_failed",
      "bundle entry is not a regular file"
    )

    Error.require!(all_zero?(prefix), "storage_failed", "bundle entry contains a path prefix")
    name = text_field!(name)
    Error.require!(name in @names, "storage_failed", "unexpected bundle entry #{inspect(name)}")
    {name, octal!(size)}
  end

  defp header!(name, size) do
    Error.require!(
      size <= @max_size,
      "storage_failed",
      "entry exceeds the POSIX USTAR 8 GiB size limit"
    )

    header =
      IO.iodata_to_binary([
        name,
        zeros(100 - byte_size(name)),
        octal(0o600, 8),
        octal(0, 8),
        octal(0, 8),
        octal(size, 12),
        octal(0, 12),
        "        ",
        "0",
        zeros(100),
        "ustar\0",
        "00",
        zeros(32 + 32 + 8 + 8 + 155 + 12)
      ])

    <<before::binary-size(148), _::binary-size(8), after_checksum::binary>> = header

    [
      before,
      String.pad_leading(Integer.to_string(checksum(header), 8), 6, "0"),
      <<0, 32>>,
      after_checksum
    ]
  end

  defp octal(number, width),
    do: [String.pad_leading(Integer.to_string(number, 8), width - 1, "0"), <<0>>]

  defp octal!(bytes) do
    value = bytes |> String.trim() |> String.trim(<<0>>) |> String.trim()

    Error.require!(
      Regex.match?(~r/\A[0-7]+\z/, value),
      "storage_failed",
      "tar header has an invalid octal number"
    )

    String.to_integer(value, 8)
  end

  defp text_field!(bytes) do
    case :binary.split(bytes, <<0>>) do
      [name, rest] ->
        Error.require!(all_zero?(rest), "storage_failed", "tar name contains hidden suffix bytes")
        name

      [name] ->
        name
    end
  end

  defp replace_checksum(<<before::binary-size(148), _::binary-size(8), rest::binary>>),
    do: <<before::binary, "        ", rest::binary>>

  defp checksum(bytes), do: bytes |> :binary.bin_to_list() |> Enum.sum()
  defp zeros(size), do: :binary.copy(<<0>>, size)
  defp all_zero?(bytes), do: bytes == zeros(byte_size(bytes))
  defp padding(size), do: rem(512 - rem(size, 512), 512)

  defp read_metadata!(_file, 0, chunks), do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  defp read_metadata!(file, remaining, chunks) do
    bytes = exact!(file, min(remaining, @chunk))
    read_metadata!(file, remaining - byte_size(bytes), [bytes | chunks])
  end

  defp zero_tail!(_file, 0), do: :ok

  defp zero_tail!(file, remaining) do
    bytes = exact!(file, min(remaining, @chunk))
    Error.require!(all_zero?(bytes), "storage_failed", "bundle has data after tar end markers")
    zero_tail!(file, remaining - byte_size(bytes))
  end

  defp transfer!(_input, _output, 0, hash),
    do: %{size: 0, hash: :crypto.hash_final(hash) |> Base.encode16(case: :lower)}

  defp transfer!(input, output, size, hash) do
    hash = transfer_chunks!(input, output, size, hash)
    %{size: size, hash: :crypto.hash_final(hash) |> Base.encode16(case: :lower)}
  end

  defp transfer_chunks!(_input, _output, 0, hash), do: hash

  defp transfer_chunks!(input, output, remaining, hash) do
    bytes = exact!(input, min(remaining, @chunk))
    if output, do: write!(output, bytes)

    transfer_chunks!(
      input,
      output,
      remaining - byte_size(bytes),
      :crypto.hash_update(hash, bytes)
    )
  end

  defp validate_report!(manifest, summary) do
    Error.require!(
      summary.size == manifest.fields["file_size"],
      "storage_failed",
      "archive report size does not match signed file_size"
    )

    Error.require!(
      summary.hash == manifest.fields["file_hash"],
      "storage_failed",
      "archive report SHA-256 does not match signed file_hash"
    )
  end

  defp validate_receipt!(manifest, receipt) do
    valid_time =
      is_map(receipt) and is_binary(receipt["stored_at"]) and receipt["stored_at"] != ""

    Error.require!(valid_time, "storage_failed", "archive receipt has invalid stored_at")

    Error.require!(
      receipt == Manifest.receipt(manifest, receipt["stored_at"]),
      "storage_failed",
      "archive receipt does not match the signed manifest projection"
    )
  end

  defp attested!(manifest, attestation_bytes) do
    attestation = json!(attestation_bytes)

    Error.require!(
      is_map(attestation) and
        Enum.sort(Map.keys(attestation)) == ~w(public_key roster_epoch roster_slot signature),
      "storage_failed",
      "archive attestation has an invalid schema"
    )

    key = attestation["public_key"]
    signature = attestation["signature"]
    epoch = attestation["roster_epoch"]
    slot = attestation["roster_slot"]

    Error.require!(
      Manifest.hex?(key, 192) and Manifest.hex?(signature, 96),
      "storage_failed",
      "archive attestation has an invalid BLS key or signature"
    )

    Error.require!(
      is_integer(epoch) and epoch >= 0 and is_integer(slot) and slot >= 0,
      "storage_failed",
      "archive attestation has an invalid roster epoch or slot"
    )

    result =
      Native.verify(
        Base.decode16!(key, case: :lower),
        Base.decode16!(signature, case: :lower),
        manifest.bytes
      )

    Error.require!(
      result == :verified,
      "storage_failed",
      "archive BLS signature verification failed: #{inspect(result)}"
    )

    %{key: key, signature: signature, roster: %{epoch: epoch, slot: slot}}
  end

  defp json!(bytes) do
    case Jason.decode(bytes, objects: :ordered_objects) do
      {:ok, value} ->
        object!(value)

      {:error, reason} ->
        Error.raise!(
          "storage_failed",
          "archive metadata is not valid UTF-8 JSON: #{Exception.message(reason)}"
        )
    end
  end

  defp object!(%Jason.OrderedObject{values: values}) do
    keys = Enum.map(values, &elem(&1, 0))

    Error.require!(
      length(keys) == MapSet.size(MapSet.new(keys)),
      "storage_failed",
      "archive metadata contains duplicate JSON members"
    )

    Map.new(values, fn {key, value} -> {key, object!(value)} end)
  end

  defp object!(values) when is_list(values), do: Enum.map(values, &object!/1)
  defp object!(value), do: value

  defp regular!(path),
    do:
      Error.require!(
        File.lstat!(path).type == :regular,
        "storage_failed",
        "archive evidence is not a regular file: #{path}"
      )

  defp opened_size!(file) do
    case :file.read_file_info(file) do
      {:ok, record} ->
        stat = File.Stat.from_record(record)

        Error.require!(
          stat.type == :regular,
          "storage_failed",
          "opened archive evidence is not a regular file"
        )

        stat.size

      {:error, reason} ->
        Error.raise!("storage_failed", "could not stat archive evidence: #{inspect(reason)}")
    end
  end

  defp with_file!(path, modes, fun) do
    file = File.open!(path, modes)

    try do
      fun.(file)
    after
      case File.close(file) do
        :ok ->
          :ok

        {:error, reason} ->
          Error.raise!("storage_failed", "could not close #{path}: #{inspect(reason)}")
      end
    end
  end

  defp exact!(_file, 0), do: ""

  defp exact!(file, size) do
    bytes = read!(file, size)

    Error.require!(
      is_binary(bytes) and byte_size(bytes) == size,
      "storage_failed",
      "archive evidence is truncated"
    )

    bytes
  end

  defp read!(file, size) do
    case :file.read(file, size) do
      {:error, reason} ->
        Error.raise!("storage_failed", "could not read archive evidence: #{inspect(reason)}")

      {:ok, bytes} ->
        bytes

      :eof ->
        :eof
    end
  end

  defp write!(file, bytes) do
    case :file.write(file, bytes) do
      :ok ->
        :ok

      {:error, reason} ->
        Error.raise!("storage_failed", "could not write bundle: #{inspect(reason)}")
    end
  end

  defp storage!(fun) do
    fun.()
  rescue
    exception in File.Error -> Error.raise!("storage_failed", Exception.message(exception))
  end
end
