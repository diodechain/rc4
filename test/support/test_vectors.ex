defmodule RC4.TestVectors do
  @moduledoc false

  def hex_to_bin!(hex) when is_binary(hex) do
    hex
    |> String.replace(" ", "")
    |> Base.decode16!(case: :mixed)
  end
end
