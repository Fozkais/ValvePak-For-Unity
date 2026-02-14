using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace ValvePak
{
	/// <summary>
	/// VPK (Valve Pak) files are uncompressed archives used to package game content.
	/// </summary>
	public partial class Package : IDisposable
	{
		sealed class SubStream : Stream, IDisposable
		{
#pragma warning disable CA2213 // Disposable fields should be disposed
			private readonly Stream baseStream;
#pragma warning restore CA2213
			private readonly long length;
			private long position;
			public SubStream(Stream baseStream, long offset, long length)
			{
				this.baseStream = baseStream;
				this.length = length;

				baseStream.Seek(offset, SeekOrigin.Begin);
			}
			public override int Read(byte[] buffer, int offset, int count)
			{
				var remaining = length - position;
				if (remaining <= 0) return 0;
				if (remaining < count) count = (int)remaining;
				var read = baseStream.Read(buffer, offset, count);
				position += read;
				return read;
			}
			public override long Position
			{
				get => position;
				set => throw new NotSupportedException();
			}
			public override long Length => length;
			public override bool CanRead => true;
			public override bool CanWrite => false;
			public override bool CanSeek => false;
			public override void Flush() => baseStream.Flush();
			public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
			public override void SetLength(long value) => throw new NotSupportedException();
			public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();
		}

		/// <summary>
		/// Gets the size in bytes of the whole file before <see cref="WholeFileChecksum"/>.
		/// </summary>
		private uint FileSizeBeforeWholeFileHash;

		/// <summary>
		/// Gets the size in bytes of the whole file before <see cref="AccessPackFileHashes"/>.
		/// </summary>
		private uint FileSizeBeforeArchiveMD5Entries;

		/// <summary>
		/// Gets the size in bytes of the whole file before <see cref="Signature"/>.
		/// </summary>
		private uint FileSizeBeforeSignature;

		/// <summary>
		/// Verify MD5 hashes provided in the VPK.
		/// </summary>
		public void VerifyHashes()
		{
			if (Version != 2)
			{
				throw new InvalidDataException("Only version 2 is supported.");
			}

			Debug.Assert(Reader != null);
			Debug.Assert(TreeChecksum != null);
			Debug.Assert(ArchiveMD5EntriesChecksum != null);
			Debug.Assert(WholeFileChecksum != null);

			byte[] hash;

			using (var subStream = new SubStream(Reader!.BaseStream, HeaderSize, (int)TreeSize))
			{
				hash = MD5Extensions.ComputeMD5(subStream);
			}

			if (!hash.SequenceEqual(TreeChecksum))
			{
				throw new InvalidDataException(
					$"File tree checksum mismatch ({BitConverter.ToString(hash)} != expected {BitConverter.ToString(TreeChecksum)})"
				);
			}

			using (var subStream2 = new SubStream(Reader.BaseStream, FileSizeBeforeArchiveMD5Entries, (int)ArchiveMD5SectionSize))
			{
				hash = MD5Extensions.ComputeMD5(subStream2);
			}

			if (!hash.SequenceEqual(ArchiveMD5EntriesChecksum))
			{
				throw new InvalidDataException(
					$"Archive MD5 entries checksum mismatch ({BitConverter.ToString(hash)} != expected {BitConverter.ToString(ArchiveMD5EntriesChecksum)})"
				);
			}

			using (var subStream3 = new SubStream(Reader.BaseStream, 0, FileSizeBeforeWholeFileHash))
			{
				hash = MD5Extensions.ComputeMD5(subStream3);
			}

			if (!hash.SequenceEqual(WholeFileChecksum))
			{
				throw new InvalidDataException(
					$"Package checksum mismatch ({BitConverter.ToString(hash)} != expected {BitConverter.ToString(WholeFileChecksum)})"
				);
			}
		}

		/// <summary>
		/// Verify hashes of individual chunk files provided in the VPK.
		/// </summary>
		/// <param name="progressReporter">If provided, will report a string with the current verification progress.</param>
		public void VerifyChunkHashes(IProgress<string>? progressReporter = null)
		{
			Stream? stream = null;
			var lastArchiveIndex = ushort.MaxValue;

			// When created by Valve, entries are sorted, and are 1MB chunks
			var allEntries = AccessPackFileHashes
				.OrderBy(file => file.Offset)
				.GroupBy(file => file.ArchiveIndex)
				.OrderBy(x => x.Key)
				.SelectMany(x => x);

			var hash = new byte[16];

			try
			{
				foreach (var entry in allEntries)
				{
					var hashTypeName = entry.HashType switch
					{
						EHashType.Blake3 => "Blake3",
						EHashType.MD5 => "MD5",
						_ => string.Empty,
					};

					progressReporter?.Report($"Verifying {hashTypeName} hash at offset {entry.Offset} in archive {entry.ArchiveIndex}.");

					if (stream == null || lastArchiveIndex != entry.ArchiveIndex)
					{
						if (lastArchiveIndex != 0x7FFF)
						{
							stream?.Close();
						}

						stream = GetFileStream(entry.ArchiveIndex);
						lastArchiveIndex = entry.ArchiveIndex;
					}
					else
					{
						var offset = entry.ArchiveIndex == 0x7FFF ? HeaderSize + TreeSize : 0;
						stream.Seek(offset, SeekOrigin.Begin);
					}

					using var subStream = new SubStream(stream, stream.Position + entry.Offset, entry.Length);

					switch (entry.HashType)
					{
						case EHashType.Blake3:
							HashUtils.ComputeSHA256(subStream, hash);
							break;

						case EHashType.MD5:
							MD5Extensions.HashData(stream, hash);
							break;

						default:
							throw new InvalidDataException($"Unrecognized hash type: {entry.HashType} ({(ushort)entry.HashType})");
					}

					if (!hash.SequenceEqual(entry.Checksum))
					{
						throw new InvalidDataException($"Package checksum mismatch ({hashTypeName}) in archive {entry.ArchiveIndex} at {entry.Offset} ({hash.ToHexString()} != expected {entry.Checksum.ToHexString()})");
					}
				}

				progressReporter?.Report("Successfully verified archive hashes.");
			}
			finally
			{
				if (lastArchiveIndex != 0x7FFF)
				{
					stream?.Close();
				}
			}
		}

		/// <summary>
		/// Verify CRC32 checksums of all files in the package.
		/// </summary>
		/// <param name="progressReporter">If provided, will report a string with the current verification progress.</param>
		public void VerifyFileChecksums(IProgress<string>? progressReporter = null)
		{
			if (Entries == null)
			{
				return;
			}

			var allEntries = Entries
				.SelectMany(file => file.Value)
				.OrderBy(file => file.Offset)
				.GroupBy(file => file.ArchiveIndex)
				.OrderBy(x => x.Key)
				.SelectMany(x => x);

			foreach (var entry in allEntries)
			{
				progressReporter?.Report($"Verifying CRC32 checksum for '{entry.GetFullPath()}' in archive {entry.ArchiveIndex}.");

				ReadEntry(entry, out var _, validateCrc: true);
			}

			progressReporter?.Report("Successfully verified file CRC32 checksums.");
		}

		/// <summary>
		/// Verifies the RSA signature.
		/// </summary>
		/// <returns>True if signature is valid, false otherwise.</returns>
		public bool IsSignatureValid()
		{
			if (PublicKey == null || Signature == null)
			{
				return true;
			}

			if (Reader == null)
			{
				return false;
			}

			AsymmetricKeyParameter rsaKey;
			try
			{
				rsaKey = PublicKeyFactory.CreateKey(PublicKey); // PublicKey = byte[] DER/PEM
			}
			catch
			{
				return false;
			}

			if (SignatureType == ESignatureType.OnlyFileChecksum)
			{
				if (WholeFileChecksum == null)
					return false;

				using var subStream3 = new SubStream(Reader.BaseStream, 0, FileSizeBeforeWholeFileHash);
				var hash = MD5Extensions.ComputeMD5(subStream3);

				if (!hash.SequenceEqual(WholeFileChecksum))
					return false;

				var signer = new RsaDigestSigner(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
				signer.Init(false, rsaKey);

				signer.BlockUpdate(hash, 0, hash.Length);
				return signer.VerifySignature(Signature);
			}

			if (SignatureType != ESignatureType.FullFile)
				return false;

			using var subStream = new SubStream(Reader.BaseStream, 0, FileSizeBeforeSignature);

			byte[] fileBytes;
			using (var ms = new MemoryStream())
			{
				subStream.CopyTo(ms);
				fileBytes = ms.ToArray();
			}

			var fullSigner = new RsaDigestSigner(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
			fullSigner.Init(false, rsaKey);
			fullSigner.BlockUpdate(fileBytes, 0, fileBytes.Length);
			return fullSigner.VerifySignature(Signature);
		}
	}
}
