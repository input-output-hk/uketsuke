defmodule Uketsuke.Campaign do
  @moduledoc """
  The public Campaign: the JSON `ukc send --campaign` fetches, and the page
  that announces it, both from the running config so neither can drift from it.
  Built once at router init; serving it is a send, not a render.
  """
  require EEx

  # file: the route segment; json: the served body, which the page's SHA-256
  # covers; page: the rendered HTML.
  @enforce_keys [:file, :json, :page]
  defstruct @enforce_keys

  # Server and client are versioned apart: a release is a repo state, ukc its
  # own code, so a server-only release cannot relabel the binary. Each version
  # is read from the file that owns it, and the page names both.
  @version Mix.Project.config()[:version]
  @client_zon Path.expand("../../client/build.zig.zon", __DIR__)
  @external_resource @client_zon
  [_, after_key] = :binary.split(File.read!(@client_zon), ~s(.version = "))
  [client_version, _] = :binary.split(after_key, ~s("))
  @client_version client_version
  @repo "https://github.com/input-output-hk/uketsuke"
  @mib 1024 * 1024

  def client_version, do: @client_version

  def new(config) do
    file = config.campaign <> ".json"

    json =
      Jason.encode!(%{
        service: config.service,
        network: config.network,
        campaign: config.campaign,
        lifetime_secs: div(config.campaign_lifetime_ms, 1000)
      })

    %__MODULE__{file: file, json: json, page: page(config, file, json)}
  end

  defp page(config, file, json) do
    tag = "v#{@version}"
    escape = &(&1 |> Plug.HTML.html_escape() |> IO.iodata_to_binary())

    render(%{
      service: escape.(config.service),
      network: escape.(config.network),
      campaign: escape.(config.campaign),
      campaign_url: escape.("#{config.service}/campaigns/#{file}"),
      campaign_path: "/campaigns/#{file}",
      lifetime_secs: div(config.campaign_lifetime_ms, 1000),
      max_file: max_file(config.max_file_bytes),
      sha256: :crypto.hash(:sha256, json) |> Base.encode16(case: :lower),
      version: @version,
      client_version: @client_version,
      tag: tag,
      repo: @repo,
      release: "#{@repo}/releases/download/#{tag}",
      binary: "ukc-#{@client_version}-x86_64-linux"
    })
  end

  defp max_file(bytes) when bytes >= @mib and rem(bytes, @mib) == 0, do: "#{div(bytes, @mib)} MiB"
  defp max_file(bytes), do: "#{bytes} bytes"

  EEx.function_from_file(:defp, :render, Path.join(__DIR__, "campaign.html.eex"), [:v])
end
