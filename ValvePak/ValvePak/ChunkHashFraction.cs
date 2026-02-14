namespace ValvePak
{
	/// <summary>
	/// Represents an entry in the VPK archive hashes section, containing checksum information for a chunk of archive data.
	/// </summary>
	public class ChunkHashFraction
	{
		/// <summary>
		///
		/// </summary>
		/// <param name="checksum"></param>
		public ChunkHashFraction(byte[] checksum)
		{
			Checksum = checksum;
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="readUInt16"></param>
		/// <param name="eHashType"></param>
		/// <param name="readUInt32"></param>
		/// <param name="u"></param>
		/// <param name="readBytes"></param>
		public ChunkHashFraction(ushort readUInt16, EHashType eHashType, uint readUInt32, uint u, byte[] readBytes)
		{
			ArchiveIndex = readUInt16;
			HashType = eHashType;
			Offset = readUInt32;
			Length = u;
			Checksum = readBytes;
		}

		/// <summary>
		/// Gets or sets the archive index.
		/// </summary>
		public ushort ArchiveIndex { get; set; }

		/// <summary>
		/// Gets or sets the hash algorithm type used for this entry.
		/// </summary>
		public EHashType HashType { get; set; }

		/// <summary>
		/// Gets or sets the offset in the package.
		/// </summary>
		public uint Offset { get; set; }

		/// <summary>
		/// Gets or sets the length in bytes.
		/// </summary>
		public uint Length { get; set; }

		/// <summary>
		/// Gets or sets the expected checksum.
		/// </summary>
		public byte[] Checksum { get; set; }
	}
}
