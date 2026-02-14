namespace ValvePak;

public static class Crc32
{
	private static readonly uint[] Table = new uint[256];

	static Crc32()
	{
		const uint poly = 0xEDB88320;
		for (uint i = 0; i < 256; i++)
		{
			uint crc = i;
			for (int j = 0; j < 8; j++)
			{
				crc = (crc & 1) != 0 ? (poly ^ (crc >> 1)) : (crc >> 1);
			}
			Table[i] = crc;
		}
	}

	public static uint Compute(byte[] bytes, int offset = 0, int count = -1)
	{
		if (count < 0) count = bytes.Length - offset;
		uint crc = 0xFFFFFFFF;
		for (int i = offset; i < offset + count; i++)
		{
			crc = Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
		}
		return ~crc;
	}
}
