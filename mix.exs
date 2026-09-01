defmodule RC4.MixProject do
  use Mix.Project

  @version "0.1.0"
  @url "https://github.com/diodechain/rc4"

  def project do
    [
      app: :rc4,
      version: @version,
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "RC4",
      description: """
      Pure Elixir RC4 stream cipher compatible with :crypto.crypto_one_time(:rc4, ...).
      """,
      package: package(),
      source_url: @url,
      aliases: aliases(),
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.28", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Diode"],
      licenses: ["MIT"],
      links: %{github: @url},
      files: ~w(lib LICENSE.md mix.exs README.md)
    ]
  end

  defp aliases do
    [
      lint: [
        "compile --warnings-as-errors",
        "format --check-formatted",
        "credo --only warning"
      ]
    ]
  end
end
