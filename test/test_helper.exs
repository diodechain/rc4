ExUnit.start()

openssl_rc4? =
  if :rc4 in (:crypto.supports()[:ciphers] || []) do
    try do
      :crypto.crypto_one_time(:rc4, <<1>>, <<2>>, false)
      true
    rescue
      _ -> false
    end
  else
    false
  end

unless openssl_rc4? do
  ExUnit.configure(exclude: [requires_openssl_rc4: true])
end

defmodule RC4.TestHelper do
  @moduledoc false

  # RFC 6229 lists keystream output; zero plaintext yields ciphertext == keystream.
  def keystream_at(key, offset, len) when is_binary(key) and offset >= 0 and len > 0 do
    key
    |> RC4.apply(:binary.copy(<<0>>, offset + len))
    |> binary_part(offset, len)
  end

  def hex_to_bin!(hex) when is_binary(hex) do
    hex
    |> String.replace(" ", "")
    |> Base.decode16!(case: :mixed)
  end
end
