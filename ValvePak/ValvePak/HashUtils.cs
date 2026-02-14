using System;
using System.IO;
using System.Security.Cryptography;

namespace ValvePak;

public static class HashUtils
{
	public static void ComputeSHA256(Stream subStream, byte[] hash)
	{
		if (subStream == null)
			throw new ArgumentNullException(nameof(subStream));
		if (hash == null || hash.Length < 32)
			throw new ArgumentException("Hash buffer must be at least 32 bytes.", nameof(hash));

		using (var sha = SHA256.Create())
		{
			var buffer = new byte[8192]; // même taille que ton Blake3 buffer
			int bytesRead;
			while ((bytesRead = subStream.Read(buffer, 0, buffer.Length)) > 0)
			{
				sha.TransformBlock(buffer, 0, bytesRead, null, 0);
			}

			// Finalize le hash
			sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

			// Copier le résultat dans ton buffer
			Array.Copy(sha.Hash, hash, 32);
		}
	}
}
