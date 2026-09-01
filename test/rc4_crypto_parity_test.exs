defmodule RC4.CryptoParityTest do
  use ExUnit.Case, async: true

  @moduletag :requires_openssl_rc4
  @profile_key <<182, 57, 1, 249, 27, 78, 124, 59, 127, 61, 120, 17, 158, 153, 118, 14, 91, 111,
                 13, 194, 43, 111, 115, 86, 86, 93, 43, 57, 56, 78, 92, 4>>

  @plan_key <<129, 216, 249, 27, 78, 124, 253, 122, 61, 120, 193, 158, 53, 18, 194, 91, 111, 12,
              194, 217, 126, 175, 86, 159, 150, 194, 71, 182, 56, 178, 92, 169>>

  defp assert_parity(key, data) do
    ref = :crypto.crypto_one_time(:rc4, key, data, false)
    assert RC4.apply(key, data) == ref
    assert RC4.apply(key, ref) == data
  end

  test "matches :crypto for RFC key1 40-bit vector inputs" do
    key = <<1, 2, 3, 4, 5>>
    data = :binary.copy(<<0>>, 32)
    assert_parity(key, data)
  end

  test "matches :crypto for RFC key2 128-bit vector inputs" do
    key = :crypto.hash(:sha256, "Internet Engineering Task Force") |> binary_part(16, 16)
    data = "Internet Engineering Task Force"
    assert_parity(key, data)
  end

  test "matches :crypto for empty plaintext" do
    assert_parity(<<1, 2, 3>>, "")
  end

  test "matches :crypto for single-byte key" do
    assert_parity(<<42>>, "test")
  end

  test "matches :crypto for 256-byte key" do
    key = :binary.copy(<<9>>, 256)
    assert_parity(key, "payload")
  end

  test "matches :crypto for key with null bytes" do
    assert_parity(<<0, 1, 0, 2>>, "same")
  end

  test "matches :crypto for large payload" do
    key = <<7, 8, 9, 10>>
    data = :binary.copy(<<0xAB>>, 64 * 1024)
    assert_parity(key, data)
  end

  test "matches :crypto for ddrive profile-style key" do
    assert_parity(@profile_key, "alice.anvil")
  end

  test "matches :crypto for ddrive plan-style key" do
    assert_parity(@plan_key, "nomad")
  end

  test "matches :crypto for SHA256-derived invite/zone key" do
    key = :crypto.hash(:sha256, "zone-password-seed")
    assert_parity(key, "INVITE1234")
  end

  test "encrypt? flag does not change :crypto RC4 output" do
    key = @profile_key
    data = "hello"

    assert :crypto.crypto_one_time(:rc4, key, data, true) ==
             :crypto.crypto_one_time(:rc4, key, data, false)
  end
end
