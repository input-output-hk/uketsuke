defmodule Uketsuke.MixProject do
  use Mix.Project

  def project do
    [
      app: :uketsuke,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: true,
      deps: deps(),
      # The application needs INBOX_CONFIG; tests exercise modules directly.
      aliases: [test: "test --no-start"]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto], mod: {Uketsuke.Application, []}]
  end

  defp deps do
    [
      {:bandit, "== 1.12.5"},
      {:plug, "== 1.20.3"},
      {:jason, "== 1.4.4"},
      {:finch, "== 0.24.0"},
      {:aws_signature, "== 0.4.3"},
      {:zigler, "== 0.16.0", runtime: false}
    ]
  end
end
