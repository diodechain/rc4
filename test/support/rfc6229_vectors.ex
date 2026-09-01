defmodule RFC6229.Vectors do
  @moduledoc false

  @key1_prefix <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>

  @key2_full :crypto.hash(:sha256, "Internet Engineering Task Force")

  @offsets [0, 256, 768, 1536, 3072]

  def key1_cases do
    [
      {40, <<1, 2, 3, 4, 5>>},
      {128, binary_part(@key1_prefix, 0, 16)},
      {256, @key1_prefix}
    ]
  end

  def key2_cases do
    [
      {128, binary_part(@key2_full, 16, 16)},
      {256, @key2_full}
    ]
  end

  def offsets, do: @offsets

  def all_cases do
    for {bits, key} <- key1_cases(), do: {:key1, bits, key}
  end

  def all_key2_cases do
    for {bits, key} <- key2_cases(), do: {:key2, bits, key}
  end

  def expected_hex(key_id, key_bits, offset) do
    table()
    |> Map.fetch!({key_id, key_bits, offset})
    |> RC4.TestVectors.hex_to_bin!()
  end

  defp table do
    %{
      {:key1, 40, 0} => "b2396305f03dc027ccc3524a0a1118a8",
      {:key1, 40, 256} => "1cfcf62b03eddb641d77dfcf7f8d8c93",
      {:key1, 40, 768} => "eb62638d4f0ba1fe9fca20e05bf8ff2b",
      {:key1, 40, 1536} => "d8729db41882259bee4f825325f5a130",
      {:key1, 40, 3072} => "ec0e11c479dc329dc8da7968fe965681",
      {:key1, 128, 0} => "9ac7cc9a609d1ef7b2932899cde41b97",
      {:key1, 128, 256} => "d39d566bc6bce3010768151549f3873f",
      {:key1, 128, 768} => "eccbe13de1fcc91c11a0b26c0bc8fa4d",
      {:key1, 128, 1536} => "ffa0b514647ec04f6306b892ae661181",
      {:key1, 128, 3072} => "c05d88abd50357f935a63c59ee537623",
      {:key1, 256, 0} => "eaa6bd25880bf93d3f5d1e4ca2611d91",
      {:key1, 256, 256} => "02e1e7056b0f623900496422943e97b6",
      {:key1, 256, 768} => "e7a7b9e9ec540d5ff43bdb12792d1b35",
      {:key1, 256, 1536} => "3e34135c79db010200767651cf263073",
      {:key1, 256, 3072} => "625a1ab00ee39a5327346bddb01a9c18",
      {:key2, 128, 0} => "720c94b63edf44e131d950ca211a5a30",
      {:key2, 128, 256} => "4847d81da4942dbc249defc48c922b9f",
      {:key2, 128, 768} => "ef2d676f1545c2c13dc680a02f4adbfe",
      {:key2, 128, 1536} => "1175da6ee756de46a53e2b075660b770",
      {:key2, 128, 3072} => "84a9218fc36e8a5f2ccfbeae53a27d25",
      {:key2, 256, 0} => "dd5bcb0018e922d494759d7c395d02d3",
      {:key2, 256, 256} => "f8cb6274db99b80b1d2012a98ed48f0e",
      {:key2, 256, 768} => "8514a5495858096f596e4bcd66b10665",
      {:key2, 256, 1536} => "8c3c13f8c2388bb73f38576e65b7c446",
      {:key2, 256, 3072} => "9ea36c525531b880ba124334f57b0b70"
    }
  end
end
