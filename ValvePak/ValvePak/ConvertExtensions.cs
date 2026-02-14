using System;

namespace ValvePak;

public static class ConvertExtensions
{
	private static readonly char[] HexAlphabet = "0123456789ABCDEF".ToCharArray();

	public static string ToHexString(this byte[] bytes)
	{
		if (bytes == null)
			throw new ArgumentNullException(nameof(bytes));

		char[] chars = new char[bytes.Length * 2];

		for (int i = 0; i < bytes.Length; i++)
		{
			int b = bytes[i];
			chars[i * 2]     = HexAlphabet[b >> 4];
			chars[i * 2 + 1] = HexAlphabet[b & 0xF];
		}

		return new string(chars);
	}
}
