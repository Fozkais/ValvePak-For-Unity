using System;
using System.IO;
using System.Security.Cryptography;

namespace ValvePak;

/// <summary>
///
/// </summary>
public static class MD5Extensions
{
	/// <summary>
	/// Return MD5Hash from byte array
	/// </summary>
	/// <param name="data"></param>
	/// <returns></returns>
	public static byte[] ComputeMD5(byte[] data)
	{
		using (var md5 = MD5.Create())
			return md5.ComputeHash(data);
	}

	/// <summary>
	/// Return MD5Hash from stream
	/// </summary>
	/// <param name="stream"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentNullException"></exception>
	public static byte[] ComputeMD5(Stream stream)
	{
		if (stream == null)
			throw new ArgumentNullException(nameof(stream));

		long originalPosition = 0;

		if (stream.CanSeek)
		{
			originalPosition = stream.Position;
			stream.Position = 0;
		}

		using (var md5 = MD5.Create())
		{
			var hash = md5.ComputeHash(stream);

			if (stream.CanSeek)
				stream.Position = originalPosition;

			return hash;
		}
	}

	public static void HashData(Stream stream, byte[] destination)
	{
		if (stream == null)
			throw new ArgumentNullException(nameof(stream));
		if (destination == null)
			throw new ArgumentNullException(nameof(destination));
		if (destination.Length < 16)
			throw new ArgumentException("MD5 hash requires at least 16 bytes.", nameof(destination));

		using (var md5 = MD5.Create())
		{
			var hash = md5.ComputeHash(stream);
			Buffer.BlockCopy(hash, 0, destination, 0, 16);
		}
	}
}
