defmodule RC4 do
  @moduledoc """
  Pure Elixir RC4 stream cipher.

  Output matches `:crypto.crypto_one_time(:rc4, key, data, _encrypt?)` on OTP builds
  whose OpenSSL still exposes RC4. RC4 is symmetric: encrypt and decrypt use the same
  XOR keystream, and the `encrypt?` flag does not change the result.

  Intended as a fallback when OpenSSL 3 omits RC4 from the default provider.
  """

  import Bitwise

  def apply(key, data) when is_binary(key) and is_binary(data) do
    s = ksa(key)
    prga(s, data)
  end

  defp ksa(key) do
    key_size = byte_size(key)
    s0 = :array.from_list(Enum.to_list(0..255))

    {s, _} =
      Enum.reduce(0..255, {s0, 0}, fn i, {s, j} ->
        ki = :binary.at(key, rem(i, key_size))
        j = rem(j + :array.get(i, s) + ki, 256)
        {:array.set(i, :array.get(j, s), :array.set(j, :array.get(i, s), s)), j}
      end)

    s
  end

  defp prga(s, data) do
    {out, _} =
      Enum.map_reduce(:binary.bin_to_list(data), {s, 0, 0}, fn byte, {s, i, j} ->
        i = rem(i + 1, 256)
        j = rem(j + :array.get(i, s), 256)
        si = :array.get(i, s)
        sj = :array.get(j, s)
        s = :array.set(i, sj, :array.set(j, si, s))
        k = :array.get(rem(:array.get(i, s) + :array.get(j, s), 256), s)
        {bxor(byte, k), {s, i, j}}
      end)

    :binary.list_to_bin(out)
  end
end
