defmodule RC4Test do
  use ExUnit.Case, async: true

  @profile_key <<182, 57, 1, 249, 27, 78, 124, 59, 127, 61, 120, 17, 158, 153, 118, 14, 91, 111,
                 13, 194, 43, 111, 115, 86, 86, 93, 43, 57, 56, 78, 92, 4>>

  @plan_key <<129, 216, 249, 27, 78, 124, 253, 122, 61, 120, 193, 158, 53, 18, 194, 91, 111, 12,
              194, 217, 126, 175, 86, 159, 150, 194, 71, 182, 56, 178, 92, 169>>

  describe "RFC 6229 reference vectors" do
    # RFC 6229 lists keystream output; zero plaintext yields ciphertext == keystream.
    test "Key 1 and Key 2 vectors at standard offsets" do
      cases = RFC6229.Vectors.all_cases() ++ RFC6229.Vectors.all_key2_cases()

      for {key_id, key_bits, key} <- cases, offset <- RFC6229.Vectors.offsets() do
        expected = RFC6229.Vectors.expected_hex(key_id, key_bits, offset)
        actual = RC4.TestHelper.keystream_at(key, offset, byte_size(expected))

        assert actual == expected,
               "mismatch for #{key_id} #{key_bits}-bit key at offset #{offset}"
      end
    end

    test "Key 1 40-bit spot check: first 16 bytes at offset 0" do
      key = <<1, 2, 3, 4, 5>>
      expected = RFC6229.Vectors.expected_hex(:key1, 40, 0)
      actual = RC4.TestHelper.keystream_at(key, 0, 16)
      assert actual == expected
    end
  end

  describe "edge cases" do
    test "empty plaintext" do
      assert RC4.apply(<<1, 2, 3>>, "") == ""
    end

    test "round-trip" do
      key = <<0xAA, 0xBB, 0xCC>>
      data = "hello world"

      encrypted = RC4.apply(key, data)
      assert RC4.apply(key, encrypted) == data
    end

    test "single-byte key" do
      encrypted = RC4.apply(<<42>>, "test")
      assert is_binary(encrypted)
      assert byte_size(encrypted) == 4
      assert RC4.apply(<<42>>, encrypted) == "test"
    end

    test "256-byte key wraps during KSA" do
      key = :binary.copy(<<9>>, 256)
      data = "payload"

      assert RC4.apply(key, RC4.apply(key, data)) == data
    end

    test "binary key with null bytes" do
      key = <<0, 1, 0, 2>>
      first = RC4.apply(key, "same")
      second = RC4.apply(key, "same")
      assert first == second
      assert RC4.apply(key, first) == "same"
    end

    test "large payload round-trip" do
      key = <<7, 8, 9, 10>>
      data = :binary.copy(<<0xAB>>, 64 * 1024)
      assert RC4.apply(key, RC4.apply(key, data)) == data
    end

    test "ddrive profile-style 32-byte key round-trip" do
      for data <- ["alice.anvil", "profile-moniker"] do
        encrypted = RC4.apply(@profile_key, data)
        assert RC4.apply(@profile_key, encrypted) == data
      end
    end

    test "ddrive plan-style 32-byte key round-trip" do
      data = "nomad"
      encrypted = RC4.apply(@plan_key, data)
      assert RC4.apply(@plan_key, encrypted) == data
    end
  end
end
